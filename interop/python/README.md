# Independent interoperability peer

This directory contains the independent Python `cryptography` consumer for
the versioned UMP/1 vectors and a live peer that speaks to `umcd` without
importing the Rust workspace. Install the pinned dependency range and run:

```sh
python -m pip install -r interop/python/requirements.txt
python -m unittest discover -s interop/python -p 'test_*.py'
```

The verifier covers identity and X25519 derivation, Initial HKDF labels,
identity binding signatures, canonical XX transcript hashes, protected
short-header packet construction, header protection, AEAD decryption, and
tamper rejection. The live runner covers version refusal, XX authentication,
stream echo, datagram acknowledgement, and persistent-identity restart over
the TCP, UDP, and experimental TLS-stream carriers:

```sh
python interop/python/live_runner.py --carrier tcp --binary target/debug/umcd
python interop/python/live_runner.py --carrier udp --binary target/debug/umcd
python interop/python/live_runner.py --carrier tls --binary target/debug/umcd
```

The TLS scenario creates a short-lived self-signed DER certificate and key in
its temporary test directory and configures the daemon to trust that exact
certificate. It is test material only; production deployments must provision
their own certificate, key, trust roots, and server name.
