# Contributing

See `spec/decisions.md` for the accepted architecture, `umeps/0001-process.md`
for the proposal process, and `GOVERNANCE.md` for roles and decisions.

Every change must pass `cargo fmt --check`, `cargo clippy -- -D warnings`,
and `cargo test --workspace`. Network-facing parsers require fuzz coverage.
