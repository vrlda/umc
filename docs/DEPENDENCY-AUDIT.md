# Dependency audit evidence

Run the locked dependency gate with:

```sh
cargo install cargo-audit --locked --version 0.22.2
bash scripts/dependency-audit.sh dependency-audit
```

The output directory contains:

- `sbom.json` from `cargo metadata --format-version 1 --locked`;
- `dependency-tree.txt` from the same locked graph;
- `cargo-audit.json` from the current RustSec advisory database; and
- `Cargo.lock`, copied from the audited checkout; and
- `dependency-report.json`, which records the lockfile digest, package count,
  advisory count, committed tree, clean-tree state, and SHA-256 hashes for all
  artifacts.

The producer rejects tracked or untracked changes before running. Scheduled or
manual CI runs [`scripts/verify-dependency-audit.sh`](../scripts/verify-dependency-audit.sh)
before retaining this directory; the verifier checks the committed tree,
lockfile digest, SBOM package count, artifact sizes/digests, and zero advisory
findings. The gate fails if the lockfile is missing, metadata cannot be
generated with `--locked`, or `cargo-audit` reports any vulnerability.
