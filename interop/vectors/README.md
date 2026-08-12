# UMP/1 independent vectors

`ump1-v0.1.json` is the first versioned vector set for the stable identity,
X25519, Initial key-schedule, identity-binding, Finished HMAC, and protected
short-session packet boundaries. It was produced with Python `cryptography`
45.0.7 rather than by the Rust implementation. The Rust conformance tests are
`crates/umc-handshake/tests/independent_vectors.rs` and
`crates/umc-session/tests/independent_packet_vectors.rs`.

The seeds in this fixture are test-only. The independent Python verifier at
`interop/python/verify_vectors.py` consumes this JSON and checks the identity,
X25519, Initial/HKDF, binding, canonical XX transcript, protected short-packet,
header-protection, AEAD, and tamper-rejection values independently of the Rust
implementation. The JSON includes the canonical XX transcript sequence. The
independent live peer at `interop/python/live_runner.py` consumes these same
protocol primitives against the real daemon over TCP, UDP, and TLS-stream; CI
archives one JSON result per carrier as cross-implementation release evidence.
