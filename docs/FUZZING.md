# Fuzzing and parser-resource evidence

The repository maintains twelve cargo-fuzz targets, each with a versioned
seed corpus:

| Target | Boundary |
| --- | --- |
| `wire_parser` | packet payload parsing in every packet space |
| `relay_frames` | relay frame decoders and relay-data payload context |
| `handshake_encoding` | handshake message encoding/decoding |
| `bundle_frame` | bundle frame decoding |
| `control_envelope` | protobuf envelopes and incremental control framing |
| `carrier_framing` | the shared bounded TCP/TLS stream-frame parser |
| `session_packet` | session-data payload parsing |
| `identity_binding` | signed identity-binding structure validation |
| `route_frames` | route request/response/error decoders |
| `plugin_manifest` | manifest JSON and capability validation |
| `db_recovery` | bounded SQLite SQL/integrity-check recovery inputs |
| `storage_recovery` | damaged/truncated SQLite files through the UMC storage open and read-only schema paths |

Run the deterministic corpus/resource report locally with:

```sh
cargo install cargo-fuzz --locked
bash scripts/fuzz-report.sh /tmp/umc-fuzz-report 1000
```

The report rejects tracked or untracked changes before running every target
against its corpus. It records the requested run count, corpus file/byte
totals, committed tree, last libFuzzer progress line, per-target peak RSS, raw
logs, and SHA-256 artifact digests in `fuzz-report.json`. CI runs the same
report on pull requests, then [`scripts/verify-fuzz-report.sh`](../scripts/verify-fuzz-report.sh)
checks exact target coverage, successful progress markers, artifact sizes and
digests, and the clean-tree flag before upload; scheduled/manual CI additionally
runs a ten-minute campaign for every target. Inputs are bounded before parser,
SQL, and storage work so the campaign measures parser/recovery behavior rather
than unbounded allocation or query execution.

The 2026-08-11 native smoke report exercised all twelve targets with ten runs
per target, passed without crashes, covered 153 corpus files (403 bytes), and
recorded per-target peak RSS in the machine-readable report (RSS is
host-dependent). The release gate retains the CI artifact and any minimized
reproducer under the corresponding corpus directory.
