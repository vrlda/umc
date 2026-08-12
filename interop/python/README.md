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
tamper rejection. It is intentionally independent of the Rust workspace.
