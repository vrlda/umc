#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 BASELINE_JSON" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
baseline=$1
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

python3 - "$baseline" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

baseline_path = Path(sys.argv[1])
try:
    record = json.loads(baseline_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read baseline manifest: {exc}") from exc

if record.get("schema") != "umc-release-baseline-v1":
    raise SystemExit("unsupported release baseline schema")
if record.get("working_tree_dirty") is not False:
    raise SystemExit("baseline was not captured from a clean working tree")
for field in ("git_commit", "git_tree"):
    value = record.get(field)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit(f"invalid {field} in release baseline")

soak = record.get("soak", {})
if soak.get("status") != "pass" or soak.get("duration_ms", 0) < 600_000:
    raise SystemExit("release baseline does not contain the required ten-minute soak")
trend = soak.get("resource_trend", {})
if trend.get("schema") != "umc-resource-trend-v1":
    raise SystemExit("missing resource trend schema")
if trend.get("elapsed_ms", 0) < soak.get("duration_ms", 0):
    raise SystemExit("resource trend ended before the recorded soak duration")
peak = trend.get("peak_queued_packets")
capacity = trend.get("queue_capacity_packets")
if not isinstance(peak, int) or not isinstance(capacity, int) or peak < 0 or capacity <= 0 or peak > capacity:
    raise SystemExit("invalid resource trend bounds")
if trend.get("iterations", 0) <= 0:
    raise SystemExit("release baseline has no soak iterations")

root = baseline_path.parent.resolve()
artifacts = record.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("release baseline has no artifact digest records")
for artifact in artifacts:
    name = artifact.get("name")
    if not isinstance(name, str) or Path(name).name != name:
        raise SystemExit("artifact path escapes the baseline directory")
    path = root / name
    if not path.is_file():
        raise SystemExit(f"missing release baseline artifact: {name}")
    content = path.read_bytes()
    if artifact.get("bytes") != len(content):
        raise SystemExit(f"artifact size mismatch: {name}")
    digest = hashlib.sha256(content).hexdigest()
    if artifact.get("sha256") != digest:
        raise SystemExit(f"artifact digest mismatch: {name}")

print(f"release baseline verified: {baseline_path}")
PY
