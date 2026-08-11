# Independent vector verifier

This directory contains the independent Python `cryptography` consumer for
the versioned UMP/1 vectors. It intentionally does not import the Rust
workspace. Install the pinned dependency range and run:

```sh
python -m pip install -r interop/python/requirements.txt
python -m unittest discover -s interop/python -p 'test_*.py'
```

The verifier covers identity and X25519 derivation, Initial HKDF labels,
identity binding signatures, canonical XX transcript hashes, protected
short-header packet construction, header protection, AEAD decryption, and
tamper rejection. The independent live peer additionally exercises the real
daemon over every stream/datagram carrier profile:

```sh
python interop/python/live_runner.py --carrier tcp --binary target/debug/umcd --result live-tcp.json
python interop/python/live_runner.py --carrier udp --binary target/debug/umcd --result live-udp.json
python interop/python/live_runner.py --carrier tls --binary target/debug/umcd --result live-tls.json
```

Each run fails closed on unsupported-version refusal, authentication, framing,
carrier-close, or data-path errors and writes a machine-readable evidence
record when `--result` is supplied.
