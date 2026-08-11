# Interoperability runner

This directory defines the UMP/1 interoperability runner contract. Both the
vector conformance path and the live carrier gate are executable now.

A runner must:

1. consume the versioned wire and handshake vectors, including malformed-input
   refusal cases;
2. start two implementations with explicit carrier and trust configuration;
3. exercise endpoint authentication, stream and datagram exchange, restart,
   version coexistence, and close/error paths;
4. record implementation versions, protocol/storage versions, carrier profile,
   vector identifier, and the exact failure classification; and
5. fail closed when a peer silently downgrades, accepts an unknown critical
   value, exceeds a resource bound, or exposes application plaintext outside
   the endpoint security boundary.

Raw hello/Initial compatibility is not part of the runner contract: UMP/1
requires an encrypted or integrity-protected Initial, and the daemon rejects
the retired unprotected layout rather than silently creating a second dialect.

The repository includes a first public vector set under `interop/vectors/`,
generated independently with Python `cryptography` and consumed by both the
Rust conformance tests and the independent verifier at
`interop/python/verify_vectors.py`, including the canonical XX transcript
sequence. `interop/python/live_runner.py` is an independent Python UMP/1 peer;
it starts the real daemon and records version refusal, XX authentication,
stream echo, datagram acknowledgement, and persistent-identity restart results
over TCP, UDP, and the experimental TLS stream carrier. CI uploads one JSON
report per carrier as the repeatable live evidence record.
