# UMC language bindings

These packages are thin clients for the daemon's local Control API. They all
use the same length-prefixed protobuf `Envelope` defined in `api/umc.proto`;
payloads can be produced by generated protobuf types or by the helpers exposed
by each package.

The bindings intentionally keep no network protocol implementation of their
own. UMP sessions, identity, routing, storage, and authorization remain owned
by `umcd` and the Rust core.

| Package | Build | Transport |
| --- | --- | --- |
| `typescript` | `npm install && npm run build` | Unix socket or Windows named-pipe path through Node `net` |
| `go` | `go test ./...` | Unix socket |
| `kotlin` | `gradle build` | JDK Unix-domain socket |
| `swift` | `swift build` | POSIX Unix socket |

All clients expose `request`/`requestChecked` plus a `getStatus` convenience
method. The raw request surface lets applications use the complete protobuf
Control API without waiting for a language-specific wrapper for every daemon
service.
