#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_DIR [SOAK_DURATION_MS]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
output_dir=$1
soak_duration_ms=${2:-600000}

case "$soak_duration_ms" in
    ''|*[!0-9]*)
        echo "SOAK_DURATION_MS must be a non-negative integer" >&2
        exit 2
        ;;
esac

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v rustc >/dev/null 2>&1 || { echo "rustc is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "release baseline requires a clean working tree" >&2
    echo "commit or otherwise remove tracked and untracked changes before running" >&2
    exit 1
fi

if [ -e "$output_dir" ]; then
    echo "output directory already exists: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

run_benchmark() {
    local package=$1
    local bench=$2
    local output="$output_dir/$bench-benchmark.txt"
    if ! cargo bench --locked --package "$package" --bench "$bench" -- --noplot >"$output" 2>&1; then
        cat "$output" >&2
        exit 1
    fi
}

run_benchmark umc-wire wire
run_benchmark umc-crypto crypto
run_benchmark umc-session session

time_args=(-l)
if /usr/bin/time -v true >/dev/null 2>&1; then
    time_args=(-v)
fi

soak_log="$output_dir/soak.txt"
soak_resource_log="$output_dir/soak-resource.txt"
if ! /usr/bin/time "${time_args[@]}" env UMC_SOAK_DURATION_MS="$soak_duration_ms" \
    cargo test --locked --package umc-simulation --lib continuous_stream_datagram_soak \
    -- --ignored --nocapture >"$soak_log" 2>"$soak_resource_log"; then
    cat "$soak_log" >&2
    cat "$soak_resource_log" >&2
    exit 1
fi

rustc_info=$(rustc -vV)
target=$(printf '%s\n' "$rustc_info" | awk '$1 == "host:" { print $2 }')
git_commit=$(git rev-parse HEAD)
git_tree=$(git rev-parse HEAD^{tree})
git_dirty=false

export UMC_BASELINE_OUTPUT="$output_dir"
export UMC_BASELINE_SOAK_MS="$soak_duration_ms"
export UMC_BASELINE_TARGET="$target"
export UMC_BASELINE_RUSTC="$rustc_info"
export UMC_BASELINE_CARGO=$(cargo -V)
export UMC_BASELINE_OS=$(uname -s)
export UMC_BASELINE_ARCH=$(uname -m)
export UMC_BASELINE_KERNEL=$(uname -r)
export UMC_BASELINE_COMMIT="$git_commit"
export UMC_BASELINE_TREE="$git_tree"
export UMC_BASELINE_DIRTY="$git_dirty"
export UMC_BASELINE_LOCK_SHA256=$(sha256_file Cargo.lock)

python3 - <<'PY'
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

output = Path(os.environ["UMC_BASELINE_OUTPUT"])
soak_output = "\n".join(
    (
        (output / "soak.txt").read_text(encoding="utf-8", errors="replace"),
        (output / "soak-resource.txt").read_text(encoding="utf-8", errors="replace"),
    )
)
trend_match = re.search(
    r"continuous soak: iterations=(?P<iterations>\d+), "
    r"stream_bytes=(?P<stream_bytes>\d+), "
    r"datagram_bytes=(?P<datagram_bytes>\d+), "
    r"elapsed_ms=(?P<elapsed_ms>\d+), "
    r"peak_queued=(?P<peak_queued>\d+), "
    r"queue_capacity=(?P<queue_capacity>\d+)",
    soak_output,
)
if trend_match is None:
    raise SystemExit("soak output is missing the resource trend line")
trend = {
    "schema": "umc-resource-trend-v1",
    "iterations": int(trend_match["iterations"]),
    "stream_bytes": int(trend_match["stream_bytes"]),
    "datagram_bytes": int(trend_match["datagram_bytes"]),
    "elapsed_ms": int(trend_match["elapsed_ms"]),
    "peak_queued_packets": int(trend_match["peak_queued"]),
    "queue_capacity_packets": int(trend_match["queue_capacity"]),
}
requested_duration_ms = int(os.environ["UMC_BASELINE_SOAK_MS"])
if (
    trend["iterations"] == 0
    or trend["elapsed_ms"] < requested_duration_ms
    or trend["peak_queued_packets"] > trend["queue_capacity_packets"]
):
    raise SystemExit("invalid soak resource trend bounds")
trend["queue_headroom_packets"] = (
    trend["queue_capacity_packets"] - trend["peak_queued_packets"]
)
(output / "resource-trend.json").write_text(
    json.dumps(trend, indent=2) + "\n", encoding="utf-8"
)
artifacts = []
for path in sorted(output.iterdir()):
    if not path.is_file():
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    artifacts.append({"name": path.name, "bytes": path.stat().st_size, "sha256": digest})

record = {
    "schema": "umc-release-baseline-v1",
    "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "git_commit": os.environ["UMC_BASELINE_COMMIT"],
    "git_tree": os.environ["UMC_BASELINE_TREE"],
    "working_tree_dirty": os.environ["UMC_BASELINE_DIRTY"] == "true",
    "host": {
        "os": os.environ["UMC_BASELINE_OS"],
        "architecture": os.environ["UMC_BASELINE_ARCH"],
        "kernel": os.environ["UMC_BASELINE_KERNEL"],
        "rust_target": os.environ["UMC_BASELINE_TARGET"],
    },
    "toolchain": {
        "cargo": os.environ["UMC_BASELINE_CARGO"],
        "rustc": os.environ["UMC_BASELINE_RUSTC"],
    },
    "benchmarks": ["umc-wire/wire", "umc-crypto/crypto", "umc-session/session"],
    "soak": {
        "test": "umc-simulation::continuous_stream_datagram_soak",
        "duration_ms": int(os.environ["UMC_BASELINE_SOAK_MS"]),
        "status": "pass",
        "resource_trend": trend,
    },
    "cargo_lock_sha256": os.environ["UMC_BASELINE_LOCK_SHA256"],
    "artifacts": artifacts,
}
(output / "baseline.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY

echo "release baseline: $output_dir"
