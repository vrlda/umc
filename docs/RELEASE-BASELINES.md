# Release benchmark and soak baselines

`scripts/release-baseline.sh` produces one reproducible evidence directory for
the release performance gate. It runs the wire, crypto, and session Criterion
benchmarks plus the full ten-minute `umc-simulation` stream/datagram soak, then
writes `baseline.json` with the commit, clean-tree state, host/toolchain,
lockfile digest, soak duration, resource trend, and SHA-256 digests for every
raw artifact. The soak also writes `resource-trend.json`, recording iterations,
payload totals, elapsed time, peak bounded-link queue depth, configured queue
capacity, and remaining queue headroom.

Run the standard baseline locally with:

```sh
bash scripts/release-baseline.sh release-baseline
```

The optional second argument overrides the soak duration for a smoke run; a
release baseline must use the default `600000` milliseconds. The scheduled or
manually dispatched CI workflow runs the default and uploads the complete
`release-baseline/` directory as one artifact. A release record may reference
that artifact only when `working_tree_dirty` is `false` and
`soak.status` is `pass`.

The raw benchmark text remains alongside the machine-readable manifest so
regressions can be compared without relying on a pass/fail summary alone. The
baseline script fails closed if the soak does not emit a valid trend line or if
the observed peak exceeds the configured queue bound.

The soak uses the normal bounded simulation windows (1 GiB connection credit
and 64 MiB per-stream credit) and continuously consumes both data types. This
keeps the run representative while exercising `MAX_STREAM_DATA` replenishment;
the session layer tracks unread-buffer pressure separately from application
consumption so a continuously-drained stream does not stall at its initial
window.
