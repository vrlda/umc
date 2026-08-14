# Changelog

## 0.2.3 — 2026-08-14

### Fixed

- Use Ubuntu's `protobuf-compiler` package in the edition matrix instead of
  downloading `protoc` through a rate-limited external action.

## 0.2.2 — 2026-08-14

### Fixed

- Install `protoc` in the edition matrix before compiling the plugin build
  script, so all three profile artifacts are checked consistently.

## 0.2.1 — 2026-08-14

### Fixed

- Keep Windows clippy clean by compiling Unix sandbox helpers only on Unix.
- Run protocol coverage against the standard edition instead of conflicting
  compile-time edition features.
- Install the Linux DBus development dependency in the edition matrix so the
  native keychain adapter can be checked on Ubuntu.

### Verified

- Standard-edition LCOV generation completes locally with all workspace tests.

## 0.2.0 — 2026-08-14

### Added

- TypeScript/Node.js, Go, Kotlin/JVM, and Swift local Control API bindings.
- Shared binding documentation and package-level build entry points.
- Product roadmap covering intentionally deferred protocol and assurance work.

### Changed

- README now describes the shipped UMC product, editions, capabilities,
  supported interfaces, and release boundaries.
- Workspace release version bumped from `0.1.0` to `0.2.0`.

### Verified

- Rust workspace format, clippy, compile checks, and affected package tests.
- Go binding tests, Swift package tests, TypeScript compilation, and Python
  binding tests.
