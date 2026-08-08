# Compatibility and release matrix

This document turns `spec/compatibility.md` into the v0.1 implementation
matrix. Experimental entries are deliberately outside the stable commitment.

| Surface | v0.1 state | Compatibility promise |
| --- | --- | --- |
| UMP wire protocol | `UMP/1` | Stable protocol version; authenticated negotiation rejects unsupported versions. |
| Local Control API | `1.0` | Protobuf additive evolution within major version 1. |
| Rust SDK | `umc-sdk 0.1` | Stable Rust daemon client and typed service helpers. |
| Python binding | stdlib client in `bindings/python` | Stable local daemon client; the handwritten protobuf subset follows `api/umc.proto`. |
| C ABI | `umc-sdk-c 0.1` | Experimental; ABI may change before a stable release. |
| TCP / UDP / LAN discovery | `ump.tcp/1`, `ump.udp/1`, `ump.lan-discovery/1` | Stable carrier profiles. |
| TLS stream | `ump.tls-stream/1` | Experimental; TLS certificate/trust provisioning is deployment-specific. |
| Storage metadata | SQLite schema v2 | Backups are accepted only for the same supported schema version. |
| Bundles | UMP bundle frames and custody | Experimental store-and-forward behavior; large-transfer and envelope details may evolve. |

Deferred capabilities are not advertised as stable features: 0-RTT early
data, multi-hop relay construction, relay multipath/store-forward mode, DHT or
internet bootstrap, process-isolated dynamic plugins, anonymous credentials,
PSI/PIR, and mix-network cover traffic.

Release notes MUST include the UMP version, Control API version, SDK versions,
carrier allocation/status, storage schema, migration notes, and security
notes. Promotion of the TLS carrier or the C ABI requires independent
interoperability and security review.
