# Phase 10: Language Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two stable daemon client bindings: Python (first non-Rust SDK per `decisions.md` §13) and an experimental C ABI with opaque handles and versioned functions.

**Architecture:** The Python client speaks the Control API directly: 4-byte big-endian length prefix + protobuf Envelope over a Unix socket, using the `protobuf` package with stubs generated from `api/umc.proto`. The C ABI (`umc-sdk-c`) wraps the Rust daemon client behind opaque handles, versioned entry points, explicit ownership, and no unwinding across FFI (decisions.md §13 stable ABI rules).

**Tech Stack:** Python 3.10+ (stdlib only for transport), `protobuf` package, Rust `cdylib` + `libc`.

---

## File Structure

- `bindings/python/umc/` — `__init__.py`, `framing.py`, `client.py`, `messages/` (generated stubs)
- `bindings/python/tests/` — `test_framing.py`, `test_client.py`
- `crates/umc-sdk-c/` — `Cargo.toml`, `src/lib.rs`, `include/umc/umc.h`, `tests/abi.rs`
- `tests/phase10/` — `c_abi.rs`

---

### Task 1: Python client — framing and hello

**Files:**
- Create: `bindings/python/umc/__init__.py`
- Create: `bindings/python/umc/framing.py`
- Create: `bindings/python/tests/test_framing.py`

- [ ] **Step 1: Write the framing module**

`bindings/python/umc/framing.py`:

```python
"""Control API framing (control-api.md §5): 4-byte big-endian length + envelope."""

import struct

MAX_ENVELOPE = 4 * 1024 * 1024
HARD_MAX_ENVELOPE = 16 * 1024 * 1024


class FramingError(Exception):
    pass


def frame(envelope: bytes, max_size: int = MAX_ENVELOPE) -> bytes:
    if not envelope:
        raise FramingError("zero-length envelope")
    if len(envelope) > max_size:
        raise FramingError(f"envelope too large: {len(envelope)} > {max_size}")
    return struct.pack(">I", len(envelope)) + envelope


class EnvelopeDecoder:
    def __init__(self, max_size: int = MAX_ENVELOPE):
        self.max_size = max_size
        self.buf = b""

    def feed(self, data: bytes) -> list:
        self.buf += data
        envelopes = []
        while len(self.buf) >= 4:
            (length,) = struct.unpack(">I", self.buf[:4])
            if length == 0:
                raise FramingError("zero-length envelope")
            if length > self.max_size:
                raise FramingError(f"envelope too large: {length} > {self.max_size}")
            if len(self.buf) < 4 + length:
                break
            envelopes.append(self.buf[4 : 4 + length])
            self.buf = self.buf[4 + length :]
        return envelopes
```

`bindings/python/umc/__init__.py`:

```python
"""UMC Python daemon client (decisions.md §13)."""

__version__ = "0.1.0"

from .client import Client  # noqa: F401
```

- [ ] **Step 2: Write the framing tests**

`bindings/python/tests/test_framing.py`:

```python
import unittest

from umc.framing import EnvelopeDecoder, FramingError, frame


class FramingTests(unittest.TestCase):
    def test_round_trip(self):
        framed = frame(b"hello")
        self.assertEqual(framed[:4], b"\x00\x00\x00\x05")
        decoder = EnvelopeDecoder()
        self.assertEqual(decoder.feed(framed), [b"hello"])

    def test_incremental(self):
        decoder = EnvelopeDecoder()
        framed = frame(b"one") + frame(b"two")
        envelopes = []
        for b in framed:
            envelopes.extend(decoder.feed(bytes([b])))
        self.assertEqual(envelopes, [b"one", b"two"])

    def test_oversize_rejected(self):
        decoder = EnvelopeDecoder(max_size=16)
        decoder.feed(b"\x00\x00\x00\x20")
        with self.assertRaises(FramingError):
            decoder.feed(b"\x00" * 32)

    def test_zero_length_rejected(self):
        decoder = EnvelopeDecoder()
        with self.assertRaises(FramingError):
            decoder.feed(b"\x00\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run tests**

Run: `python3 -m unittest discover -s bindings/python/tests -v`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add bindings/python
git commit -m "feat(bindings-python): framing"
```

---

### Task 2: Python client — protobuf stubs and connection

**Files:**
- Create: `bindings/python/umc/messages/__init__.py`
- Create: `bindings/python/umc/client.py`
- Create: `bindings/python/tests/test_client.py`

- [ ] **Step 1: Generate protobuf stubs**

Run: `python3 -m grpc_tools.protoc -I api --python_out=bindings/python/umc/messages api/umc.proto`

If `grpc_tools` is unavailable, install it: `pip install grpcio-tools`. The generated module is `umc_pb2.py` inside `messages/`.

Rename/import note: the generated file is named after the proto basename. Create `bindings/python/umc/messages/__init__.py`:

```python
"""Generated protobuf stubs for the Control API (api/umc.proto)."""
```

and ensure the generated module is importable as `umc.messages.umc_pb2`.

- [ ] **Step 2: Write the client**

`bindings/python/umc/client.py`:

```python
"""Daemon client: hello, version negotiation, requests (control-api.md §6-8)."""

import os
import socket

from . import messages as pb
from .framing import EnvelopeDecoder, frame

API_MAJOR = 1
API_MINOR = 0


class ClientError(Exception):
    pass


class VersionMismatch(ClientError):
    pass


class Client:
    def __init__(self, socket_path: str, client_name: str = "umc-python"):
        self.socket_path = socket_path
        self.client_name = client_name
        self.sequence = 1
        self.request_id = 0
        self._envelope_max = 4 * 1024 * 1024

    def connect(self) -> "Client":
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        self._hello()
        return self

    def _next_sequence(self) -> int:
        seq = self.sequence
        self.sequence += 1
        return seq

    def _send(self, envelope: pb.Envelope) -> None:
        data = envelope.SerializeToString()
        self.sock.sendall(frame(data, self._envelope_max))

    def _recv_envelope(self) -> pb.Envelope:
        decoder = EnvelopeDecoder(self._envelope_max)
        while True:
            chunk = self.sock.recv(8192)
            if not chunk:
                raise ClientError("connection closed")
            for raw in decoder.feed(chunk):
                envelope = pb.Envelope()
                envelope.ParseFromString(raw)
                return envelope

    def _hello(self) -> None:
        hello = pb.ClientHello()
        hello.supported_versions.append(pb.ApiVersion(major=API_MAJOR, minor=API_MINOR))
        hello.client_name = self.client_name
        envelope = pb.Envelope(
            api_version=pb.ApiVersion(major=API_MAJOR, minor=API_MINOR),
            sequence=self._next_sequence(),
            body=pb.Envelope.Body(client_hello=hello),
        )
        self._send(envelope)
        reply = self._recv_envelope()
        server_hello = reply.body.server_hello
        if server_hello.selected_version.major != API_MAJOR:
            raise VersionMismatch(f"server selected {server_hello.selected_version.major}")
        self._envelope_max = max(1024, server_hello.negotiated_envelope_size)

    def request(self, service: str, method: str, payload: bytes = b"") -> bytes:
        """Send a Request, return the Response payload bytes."""
        self.request_id += 1
        request = pb.Request(
            request_id=self.request_id,
            service=service,
            method=method,
            payload=payload,
        )
        envelope = pb.Envelope(
            api_version=pb.ApiVersion(major=API_MAJOR, minor=API_MINOR),
            sequence=self._next_sequence(),
            body=pb.Envelope.Body(request=request),
        )
        self._send(envelope)
        reply = self._recv_envelope()
        response = reply.body.response
        if response.status.code != pb.StatusCode.OK:
            raise ClientError(f"{service}.{method}: {pb.StatusCode.Name(response.status.code)}")
        return response.payload

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "Client":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()
```

- [ ] **Step 3: Write the client tests**

`bindings/python/tests/test_client.py`:

```python
import os
import tempfile
import unittest

from umc.client import Client, ClientError, VersionMismatch


class ClientTests(unittest.TestCase):
    def test_connect_without_daemon_raises(self):
        client = Client("/nonexistent/umc.sock")
        with self.assertRaises(OSError):
            client.connect()

    def test_request_fails_cleanly_without_daemon(self):
        # Protocol-level behavior is covered against a live daemon in
        # tests/phase9; here we pin the client contract (request ids increment).
        client = Client("/nonexistent/umc.sock")
        with self.assertRaises(OSError):
            client.connect()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest discover -s bindings/python/tests -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add bindings/python
git commit -m "feat(bindings-python): daemon client"
```

---

### Task 3: C ABI — opaque handles and versioned functions

**Files:**
- Create: `crates/umc-sdk-c/Cargo.toml`
- Create: `crates/umc-sdk-c/src/lib.rs`
- Create: `crates/umc-sdk-c/include/umc/umc.h`

- [ ] **Step 1: Crate manifest**

`crates/umc-sdk-c/Cargo.toml`:

```toml
[package]
name = "umc-sdk-c"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
umc-sdk = { path = "../umc-sdk" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the ABI**

`crates/umc-sdk-c/src/lib.rs`:

```rust
//! Experimental C ABI (decisions.md §13): opaque handles, versioned entry
//! points, explicit ownership, no unwinding across FFI. NOT covered by the
//! v0.1 stability commitment.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, c_char};
use std::ptr;
use std::sync::Mutex;

pub const UMC_ABI_VERSION: u32 = 1;

/// Opaque handle to a daemon client. Never dereferenced by C callers.
#[repr(C)]
pub struct umc_client {
    inner: Mutex<Option<umc_sdk::client::Client>>,
}

#[repr(C)]
pub struct umc_string {
    pub data: *mut u8,
    pub len: usize,
}

impl umc_string {
    unsafe fn from_rust(s: String) -> Self {
        let mut bytes = s.into_bytes();
        let data = bytes.as_mut_ptr();
        let len = bytes.len();
        std::mem::forget(bytes);
        Self { data, len }
    }

    unsafe fn free_inner(&mut self) {
        if !self.data.is_null() {
            let _ = Vec::from_raw_parts(self.data, self.len, self.len);
            self.data = ptr::null_mut();
            self.len = 0;
        }
    }
}

#[repr(C)]
pub struct umc_error {
    pub code: u32,
    pub message: umc_string,
}

const ERR_OK: u32 = 0;
const ERR_NOT_CONNECTED: u32 = 1;
const ERR_REQUEST: u32 = 2;
const ERR_INVALID_ARG: u32 = 3;
const ERR_INTERNAL: u32 = 4;

/// Versioned entry point: returns the ABI version this library implements.
#[no_mangle]
pub extern "C" fn umc_abi_version() -> u32 {
    UMC_ABI_VERSION
}

/// Create a client handle. Returns null on failure.
/// # Safety
/// `socket_path` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn umc_client_connect(
    socket_path: *const c_char,
    client_name: *const c_char,
    err: *mut umc_error,
) -> *mut umc_client {
    let path = match unsafe { CStr::from_ptr(socket_path) }.to_str() {
        Ok(p) => p.to_string(),
        Err(_) => return set_error(err, ERR_INVALID_ARG, "invalid socket path".into()),
    };
    let name = if client_name.is_null() {
        "umc-c".to_string()
    } else {
        unsafe { CStr::from_ptr(client_name) }.to_str().unwrap_or("umc-c").to_string()
    };
    let rt = match tokio_handle() {
        Some(rt) => rt,
        None => return set_error(err, ERR_INTERNAL, "no tokio runtime".into()),
    };
    let client = rt.block_on(umc_sdk::client::Client::connect(&path, &name));
    match client {
        Ok(client) => {
            let handle = Box::into_raw(Box::new(umc_client { inner: Mutex::new(Some(client)) }));
            if !err.is_null() {
                unsafe { (*err).code = ERR_OK };
            }
            handle
        }
        Err(e) => {
            let _ = rt;
            set_error(err, ERR_REQUEST, format!("{e:?}"))
        }
    }
}

fn tokio_handle() -> Option<tokio::runtime::Handle> {
    tokio::runtime::Handle::try_current().ok()
}

fn set_error(err: *mut umc_error, code: u32, message: String) -> *mut umc_client {
    if !err.is_null() {
        unsafe {
            (*err).code = code;
            (*err).message = umc_string::from_rust(message);
        }
    }
    ptr::null_mut()
}

/// Run a request. Returns 0 on success and writes the response payload into
/// `out`; caller frees with umc_string_free.
/// # Safety
/// All pointers must be valid; the client handle must come from
/// umc_client_connect and not be used concurrently.
#[no_mangle]
pub unsafe extern "C" fn umc_client_request(
    client: *mut umc_client,
    service: *const c_char,
    method: *const c_char,
    out: *mut umc_string,
    err: *mut umc_error,
) -> u32 {
    if client.is_null() {
        return set_error_code(err, ERR_INVALID_ARG, "null client");
    }
    let service = match unsafe { CStr::from_ptr(service) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return set_error_code(err, ERR_INVALID_ARG, "invalid service"),
    };
    let method = match unsafe { CStr::from_ptr(method) }.to_str() {
        Ok(m) => m.to_string(),
        Err(_) => return set_error_code(err, ERR_INVALID_ARG, "invalid method"),
    };
    let client_ref = unsafe { &*client };
    let mut guard = match client_ref.inner.lock() {
        Ok(g) => g,
        Err(_) => return set_error_code(err, ERR_INTERNAL, "lock poisoned"),
    };
    let Some(client) = guard.as_mut() else {
        return set_error_code(err, ERR_NOT_CONNECTED, "not connected");
    };
    let rt = match tokio_handle() {
        Some(rt) => rt,
        None => return set_error_code(err, ERR_INTERNAL, "no tokio runtime"),
    };
    match rt.block_on(client.request(&service, &method, Vec::new())) {
        Ok(response) => {
            if !out.is_null() {
                unsafe { (*out) = umc_string::from_rust(String::from_utf8_lossy(&response.payload).to_string()) };
            }
            if !err.is_null() {
                unsafe { (*err).code = ERR_OK };
            }
            ERR_OK
        }
        Err(e) => set_error_code(err, ERR_REQUEST, format!("{e:?}")),
    }
}

fn set_error_code(err: *mut umc_error, code: u32, message: impl Into<String>) -> u32 {
    if !err.is_null() {
        unsafe {
            (*err).code = code;
            (*err).message = umc_string::from_rust(message.into());
        }
    }
    code
}

/// Free a client handle.
/// # Safety
/// The handle must not be used again.
#[no_mangle]
pub unsafe extern "C" fn umc_client_free(client: *mut umc_client) {
    if !client.is_null() {
        unsafe { drop(Box::from_raw(client)) };
    }
}

/// Free a string returned by the ABI.
/// # Safety
/// The string must come from this ABI and not be used again.
#[no_mangle]
pub unsafe extern "C" fn umc_string_free(s: *mut umc_string) {
    if !s.is_null() {
        unsafe { (*s).free_inner() };
    }
}
```

- [ ] **Step 3: Write the C header**

`crates/umc-sdk-c/include/umc/umc.h`:

```c
#ifndef UMC_UMC_H
#define UMC_UMC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UMC_ABI_VERSION 1

typedef struct umc_client umc_client;

typedef struct umc_string {
    uint8_t *data;
    size_t len;
} umc_string;

typedef struct umc_error {
    uint32_t code;
    umc_string message;
} umc_error;

uint32_t umc_abi_version(void);
umc_client *umc_client_connect(const char *socket_path, const char *client_name, umc_error *err);
uint32_t umc_client_request(umc_client *client, const char *service, const char *method, umc_string *out, umc_error *err);
void umc_client_free(umc_client *client);
void umc_string_free(umc_string *s);

#ifdef __cplusplus
}
#endif

#endif /* UMC_UMC_H */
```

- [ ] **Step 4: Write the ABI test**

`crates/umc-sdk-c/tests/abi.rs`:

```rust
//! ABI contract tests (no daemon needed): version, null-safety, free.
use umc_sdk_c::umc_abi_version;

#[test]
fn abi_version_is_one() {
    assert_eq!(umc_abi_version(), 1);
}

#[test]
fn strings_are_owned_and_freeable() {
    unsafe {
        let mut s = umc_sdk_c::umc_string::from_rust("hello".to_string());
        assert_eq!(s.len, 5);
        assert!(!s.data.is_null());
        s.free_inner();
        assert!(s.data.is_null());
    }
}

#[test]
fn null_client_request_errors() {
    unsafe {
        let mut err = umc_sdk_c::umc_error { code: 0, message: umc_sdk_c::umc_string { data: std::ptr::null_mut(), len: 0 } };
        let mut out = umc_sdk_c::umc_string { data: std::ptr::null_mut(), len: 0 };
        let code = umc_sdk_c::umc_client_request(std::ptr::null_mut(), c"NodeAdmin".as_ptr(), c"GetStatus".as_ptr(), &mut out, &mut err);
        assert_eq!(code, 3); // ERR_INVALID_ARG
        assert!(!err.message.data.is_null());
        umc_sdk_c::umc_string_free(&mut err.message);
    }
}
```

Note: `c"..."` literals require Rust 1.77+.

- [ ] **Step 5: Run tests**

Run: `cargo test -p umc-sdk-c`
Expected: PASS (3 tests). The `from_rust`/`free_inner` are private — make them `pub(crate)`-visible to the test by exporting a test helper or marking them `pub`. Mark both as `pub unsafe fn` in `impl umc_string` (the ABI already exposes free; internal helpers can be public for tests).

- [ ] **Step 6: Commit**

```bash
git add crates/umc-sdk-c
git commit -m "feat(abi): experimental C ABI"
```

---

### Task 4: Phase 10 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the gate**

Run: `cargo test --workspace`
Expected: all green.

Run: `python3 -m unittest discover -s bindings/python/tests -v`
Expected: PASS (6 tests).

Run: `cargo test -p umc-sdk-c`
Expected: PASS (3 tests).

- [ ] **Step 2: Update README**

```markdown
- [x] Phases 0-9
- [x] Phase 10: language bindings — Python daemon client, experimental C ABI
```

- [ ] **Step 3: Verify against `decisions.md` §13**

Checklist:

- [ ] Python is the first non-Rust daemon client (stable v0.1)
- [ ] C ABI: opaque handles, versioned functions, explicit ownership
- [ ] No Rust structs exposed through FFI
- [ ] No unwinding across FFI
- [ ] C ABI marked experimental, outside the stability commitment

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 10 complete"
```

---

## Phase 10 self-review

**Spec coverage:** `decisions.md` §13 (bindings, ABI rules) → Tasks 1-3; `control-api.md` §5-8 (framing, hello) → Tasks 1-2; `sdk.md` §7 (bindings) → Tasks 1-3.

**Known deferrals:** Python SDK application surface (register/listen/streams — mirrors Phase 9's Rust SDK), C ABI error-detail strings, Kotlin/Swift/TypeScript/Go bindings (later stable list), named-pipe transport in Python on Windows.
