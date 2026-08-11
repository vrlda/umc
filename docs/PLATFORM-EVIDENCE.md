# Optional Tier-2 platform evidence

`scripts/platform-evidence.sh` is the repeatable platform gate. It requires a
clean checkout, runs the
locked workspace test suite, builds the release `umcd` binary, and records the
host architecture, Rust target/toolchain, commit state, lockfile digest, and
release-binary digest in a machine-readable `umc-platform-evidence-v1` record.

The manually dispatched CI job runs it natively on `ubuntu-24.04-arm`, asserts
`uname -m` is `aarch64`, and uploads `aarch64-platform-evidence.json` as an
optional artifact. The same script can be run locally on a supported host:

```sh
bash scripts/platform-evidence.sh platform-evidence.json
```

An evidence record is valid only when:

1. `verification.workspace_tests` and `verification.release_build` are
   `pass`;
2. `host.rust_target` matches the intended release target;
3. `working_tree_dirty` is `false` for release evidence; and
4. the uploaded binary digest is retained with the matching lockfile digest
   and commit.

`scripts/verify-platform-evidence.sh` re-checks the schema, clean-tree and
commit binding, workspace/build statuses, Cargo.lock digest, and release-binary
digest. The repository can capture native macOS arm64 evidence from this same script.
Linux aarch64 is Tier-2 for v0.1, so its artifact is useful portability evidence
but is not required for a Tier-1 release claim.
