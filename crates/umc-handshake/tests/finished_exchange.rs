//! The finished exchange (handshake.md §19-20): the wire messages each
//! side's helpers produce verify on the counterpart, and tampered MACs or
//! signatures are refused.
use umc_crypto::signatures::{
    IdentityKeyPair, IdentityPublicKey, StaticHandshakeKeyPair, StaticHandshakePublicKey,
};
use umc_handshake::encoding::{CLIENT_AUTH, CLIENT_HELLO, SERVER_HELLO};
use umc_handshake::identity::{endpoint_id, IdentityBinding};
use umc_handshake::transcript::Transcript;
use umc_handshake::xx::{
    build_client_auth_plaintext, build_server_finished, client_signature_input,
    complete_client_side, encrypt_client_auth, verify_client_finished,
    verify_server_auth_signature, verify_server_finished_and_build_confirmation, ClientHello,
    ServerHello, CRYPTO_PROFILE, MODE_XX,
};
use umc_types::runtime::EntropySource;

struct TestEntropy;

impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0xCD);
    }
}

/// The wire messages of one full XX exchange, driven with the shared
/// helpers exactly as the T13 driver lays them out. The DH chain uses the
/// client's EPHEMERAL standing in for the static (the live path's
/// provisional, handshake.md §18), so both sides derive the same secret4.
struct DriveContext {
    carrier_binding: &'static [u8],
    hello_bytes: Vec<u8>,
    server_hello_bytes: Vec<u8>,
    handshake_secret4: [u8; 32],
    server_identity_public_key: IdentityPublicKey,
    server_endpoint_id: [u8; 32],
    client_endpoint_id: [u8; 32],
    server_static_public_key: [u8; 32],
    client_static_public_key: [u8; 32],
    client_auth_body: Vec<u8>,
    server_finished: Vec<u8>,
    client_finished: [u8; 32],
}

/// The client's `CLIENT_AUTH` message body, mirroring the driver: client
/// static key + identity binding + transcript signature, sealed with the
/// client-auth key derived from secret3 and the transcript before the
/// message is appended.
#[allow(clippy::too_many_lines)]
fn drive_round_trip() -> DriveContext {
    let client_identity = IdentityKeyPair::generate();
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let server_identity = IdentityKeyPair::generate();
    let server_static = StaticHandshakeKeyPair::generate();
    let carrier_binding = b"ump.tcp/1";

    let hello = ClientHello::new(&TestEntropy, &client_ephemeral);
    let hello_bytes = hello.encode().expect("hello");

    // SERVER_HELLO, exactly as the driver builds it.
    let server_ephemeral = StaticHandshakeKeyPair::generate();
    let mut server_random = [0u8; 32];
    TestEntropy.fill(&mut server_random);
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    transcript
        .update_message(CLIENT_HELLO, &hello_bytes)
        .expect("transcript");
    let dh_ee = server_ephemeral
        .diffie_hellman(&StaticHandshakePublicKey(hello.client_ephemeral_public_key));
    let extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);
    let binding = IdentityBinding::sign(
        &server_identity,
        &server_static.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    );
    let server_auth_transcript = transcript.hash;
    let encrypted_auth = umc_handshake::xx::encrypt_server_auth(
        &extract1,
        &server_auth_transcript,
        &umc_handshake::xx::ServerAuthBlock {
            server_static_public_key: server_static.public().0,
            server_identity_binding: {
                let mut bytes = binding.signed_bytes();
                bytes.extend_from_slice(&binding.signature);
                bytes
            },
            server_delegation_chain: Vec::new(),
        },
        &server_ephemeral.public().0,
        &server_random,
        CRYPTO_PROFILE,
    )
    .expect("encrypt auth");
    let server_hello = ServerHello {
        server_random,
        server_ephemeral_public_key: server_ephemeral.public().0,
        selected_protocol_version: 1,
        selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: MODE_XX.to_vec(),
        encrypted_server_authentication: encrypted_auth,
        // The driver carries the server's canonical capabilities hash in
        // the first 32 bytes of the padding (compatibility.md §5.4).
        padding: {
            let mut padding =
                umc_handshake::xx::capabilities_hash(&umc_handshake::xx::canonical_capabilities())
                    .to_vec();
            padding.extend_from_slice(&[0u8; 32]);
            padding
        },
    };
    let server_hello_bytes = server_hello.encode().expect("server hello");
    transcript
        .update_message(SERVER_HELLO, &server_hello_bytes)
        .expect("transcript");

    // Client continuation: session secrets, secret4, and the server's
    // identity recovered from its auth block (provisional chain: the
    // ephemeral stands in for the static).
    let out = complete_client_side(
        &client_identity,
        &client_ephemeral,
        &client_ephemeral,
        &hello,
        &server_hello,
        &TestEntropy,
        carrier_binding,
    )
    .expect("client side");
    let client_eid = endpoint_id(&client_identity.public());
    let sig_input = client_signature_input(
        &out.transcript_hash,
        &client_eid,
        &out.server_endpoint_id,
        &client_ephemeral.public().0,
        &out.server_static_public_key,
    );
    let signature = client_identity.sign(&sig_input);
    let client_binding = IdentityBinding::sign(
        &client_identity,
        &client_ephemeral.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    );
    let plaintext =
        build_client_auth_plaintext(&client_ephemeral.public().0, &client_binding, &signature);
    let ciphertext = encrypt_client_auth(&out.client_auth_key, &out.transcript_hash, &plaintext);
    let mut client_auth_body = Vec::new();
    umc_wire::bytes::encode(&mut client_auth_body, &ciphertext, 16_384).expect("auth body");

    // Server side: append CLIENT_AUTH and build SERVER_FINISHED over the
    // transcript hash AFTER CLIENT_AUTH (handshake.md §19).
    transcript
        .update_message(CLIENT_AUTH, &client_auth_body)
        .expect("transcript");
    let server_eid = endpoint_id(&server_identity.public());
    let server_finished = build_server_finished(
        &out.handshake_secret4,
        &transcript.hash,
        &server_identity,
        &server_eid,
        &client_eid,
        &server_static.public().0,
        &client_ephemeral.public().0,
    );

    // Client side: verify SERVER_FINISHED and build CLIENT_FINISHED.
    let mut client_transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    client_transcript
        .update_message(CLIENT_HELLO, &hello_bytes)
        .expect("transcript");
    client_transcript
        .update_message(SERVER_HELLO, &server_hello_bytes)
        .expect("transcript");
    let client_finished = verify_server_finished_and_build_confirmation(
        &mut client_transcript,
        &out.handshake_secret4,
        &out.server_identity_public_key,
        &out.server_endpoint_id,
        &client_eid,
        &out.server_static_public_key,
        &client_ephemeral.public().0,
        &client_auth_body,
        &server_finished,
    )
    .expect("client verifies server finished");

    // Server side: verify the client's confirmation MAC.
    let mut server_transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    server_transcript
        .update_message(CLIENT_HELLO, &hello_bytes)
        .expect("transcript");
    server_transcript
        .update_message(SERVER_HELLO, &server_hello_bytes)
        .expect("transcript");
    verify_client_finished(
        &out.handshake_secret4,
        &mut server_transcript,
        &client_auth_body,
        &server_finished,
        &client_finished,
    )
    .expect("server verifies client finished");

    DriveContext {
        carrier_binding,
        hello_bytes,
        server_hello_bytes,
        handshake_secret4: out.handshake_secret4,
        server_identity_public_key: out.server_identity_public_key,
        server_endpoint_id: out.server_endpoint_id,
        client_endpoint_id: client_eid,
        server_static_public_key: out.server_static_public_key,
        client_static_public_key: client_ephemeral.public().0,
        client_auth_body,
        server_finished,
        client_finished,
    }
}

/// The client half of the finished exchange against `server_finished`.
fn client_verify(ctx: &DriveContext, server_finished: &[u8]) -> Result<[u8; 32], String> {
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, ctx.carrier_binding);
    transcript
        .update_message(CLIENT_HELLO, &ctx.hello_bytes)
        .map_err(|e| format!("{e:?}"))?;
    transcript
        .update_message(SERVER_HELLO, &ctx.server_hello_bytes)
        .map_err(|e| format!("{e:?}"))?;
    verify_server_finished_and_build_confirmation(
        &mut transcript,
        &ctx.handshake_secret4,
        &ctx.server_identity_public_key,
        &ctx.server_endpoint_id,
        &ctx.client_endpoint_id,
        &ctx.server_static_public_key,
        &ctx.client_static_public_key,
        &ctx.client_auth_body,
        server_finished,
    )
}

/// The server half of the finished exchange against `client_finished`.
fn server_verify(ctx: &DriveContext, client_finished: &[u8]) -> Result<(), String> {
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, ctx.carrier_binding);
    transcript
        .update_message(CLIENT_HELLO, &ctx.hello_bytes)
        .map_err(|e| format!("{e:?}"))?;
    transcript
        .update_message(SERVER_HELLO, &ctx.server_hello_bytes)
        .map_err(|e| format!("{e:?}"))?;
    verify_client_finished(
        &ctx.handshake_secret4,
        &mut transcript,
        &ctx.client_auth_body,
        &ctx.server_finished,
        client_finished,
    )
}

/// The full finished exchange round-trips: the client verifies the
/// server's `SERVER_FINISHED` (MAC + signature) and produces a
/// `CLIENT_FINISHED` confirmation that the server accepts.
#[test]
fn finished_exchange_round_trip() {
    let ctx = drive_round_trip();
    assert_eq!(ctx.server_finished.len(), 96, "signature (64) + MAC (32)");
    assert_eq!(ctx.client_finished.len(), 32, "confirmation MAC");
    assert_eq!(
        client_verify(&ctx, &ctx.server_finished).expect("client verifies"),
        ctx.client_finished,
        "the confirmation MAC the client transmits must match the round trip"
    );
    server_verify(&ctx, &ctx.client_finished).expect("server verifies");
}

/// A flipped byte in the server's finished MAC fails the client's
/// verification; the handshake is refused.
#[test]
fn tampered_server_mac_is_refused() {
    let ctx = drive_round_trip();
    let mut tampered = ctx.server_finished.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let error = client_verify(&ctx, &tampered).expect_err("tampered MAC");
    assert!(error.contains("MAC"), "{error}");
}

/// A flipped byte in the server's signature fails the client's
/// verification; the handshake is refused.
#[test]
fn tampered_server_signature_is_refused() {
    let ctx = drive_round_trip();
    let mut tampered = ctx.server_finished.clone();
    tampered[0] ^= 0x01;
    let error = client_verify(&ctx, &tampered).expect_err("tampered signature");
    assert!(error.contains("signature"), "{error}");
}

/// A truncated `SERVER_FINISHED` is refused before any MAC comparison.
#[test]
fn truncated_server_finished_is_refused() {
    let ctx = drive_round_trip();
    let error = client_verify(&ctx, &ctx.server_finished[..64]).expect_err("truncated");
    assert!(error.contains("truncated"), "{error}");
}

/// A flipped byte in the client's confirmation MAC fails the server's
/// verification; the session is refused.
#[test]
fn tampered_client_confirmation_is_refused() {
    let ctx = drive_round_trip();
    let mut tampered = ctx.client_finished;
    tampered[0] ^= 0x01;
    let error = server_verify(&ctx, &tampered).expect_err("tampered confirmation");
    assert!(error.contains("MAC"), "{error}");
}

/// The extracted signature verifier accepts the honest signature and
/// rejects a tampered one (the T13 driver's `server_sig_input_client`).
#[test]
fn verify_server_auth_signature_accepts_and_rejects() {
    let ctx = drive_round_trip();
    let signature: [u8; 64] = ctx.server_finished[..64].try_into().expect("signature");
    let transcript_before = {
        let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, ctx.carrier_binding);
        transcript
            .update_message(CLIENT_HELLO, &ctx.hello_bytes)
            .expect("transcript");
        transcript
            .update_message(SERVER_HELLO, &ctx.server_hello_bytes)
            .expect("transcript");
        transcript
            .update_message(CLIENT_AUTH, &ctx.client_auth_body)
            .expect("transcript");
        transcript.hash
    };
    assert!(verify_server_auth_signature(
        &ctx.server_identity_public_key,
        &transcript_before,
        &ctx.server_endpoint_id,
        &ctx.client_endpoint_id,
        &ctx.server_static_public_key,
        &ctx.client_static_public_key,
        &signature,
    ));
    let mut tampered = signature;
    tampered[0] ^= 0x01;
    assert!(!verify_server_auth_signature(
        &ctx.server_identity_public_key,
        &transcript_before,
        &ctx.server_endpoint_id,
        &ctx.client_endpoint_id,
        &ctx.server_static_public_key,
        &ctx.client_static_public_key,
        &tampered,
    ));
    // The signature binds the transcript: a different snapshot refuses.
    let mut other_hash = transcript_before;
    other_hash[0] ^= 0x01;
    assert!(!verify_server_auth_signature(
        &ctx.server_identity_public_key,
        &other_hash,
        &ctx.server_endpoint_id,
        &ctx.client_endpoint_id,
        &ctx.server_static_public_key,
        &ctx.client_static_public_key,
        &signature,
    ));
}
