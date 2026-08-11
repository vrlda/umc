#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 FUZZ_REPORT_JSON" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
report=$1
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

python3 - "$report" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_TARGETS = {
    "wire_parser",
    "relay_frames",
    "handshake_encoding",
    "bundle_frame",
    "control_envelope",
    "carrier_framing",
    "session_packet",
    "identity_binding",
    "route_frames",
    "plugin_manifest",
    "db_recovery",
    "storage_recovery",
}

report_path = Path(sys.argv[1])
try:
    record = json.loads(report_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read fuzz report: {exc}") from exc

if record.get("schema") != "umc-fuzz-report-v1":
    raise SystemExit("unsupported fuzz report schema")
if record.get("status") != "pass":
    raise SystemExit("fuzz report did not pass")
if record.get("working_tree_dirty") is not False:
    raise SystemExit("fuzz evidence was not captured from a clean working tree")
for field in ("git_commit", "git_tree"):
    value = record.get(field)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit(f"invalid {field} in fuzz report")
runs = record.get("runs_per_target")
if not isinstance(runs, int) or runs <= 0:
    raise SystemExit("fuzz report has no positive run count")

targets = record.get("targets")
if not isinstance(targets, list) or any(not isinstance(item, dict) for item in targets):
    raise SystemExit("fuzz report has malformed target records")
target_names = [item.get("name") for item in targets]
if any(not isinstance(name, str) for name in target_names):
    raise SystemExit("fuzz report has malformed target names")
if set(target_names) != EXPECTED_TARGETS:
    raise SystemExit("fuzz report does not cover exactly the expected targets")
if len(targets) != len(EXPECTED_TARGETS):
    raise SystemExit("fuzz report contains duplicate targets")

root = report_path.parent.resolve()
artifacts = record.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("fuzz report has no artifact digest records")
by_name = {}
for artifact in artifacts:
    if not isinstance(artifact, dict):
        raise SystemExit("fuzz report has a malformed artifact record")
    name = artifact.get("name")
    if not isinstance(name, str) or Path(name).name != name:
        raise SystemExit("fuzz artifact path escapes the report directory")
    if name in by_name:
        raise SystemExit(f"duplicate fuzz artifact: {name}")
    path = root / name
    if not path.is_file():
        raise SystemExit(f"missing fuzz artifact: {name}")
    content = path.read_bytes()
    if artifact.get("bytes") != len(content):
        raise SystemExit(f"fuzz artifact size mismatch: {name}")
    digest = hashlib.sha256(content).hexdigest()
    if artifact.get("sha256") != digest:
        raise SystemExit(f"fuzz artifact digest mismatch: {name}")
    by_name[name] = path

for target in targets:
    name = target.get("name")
    if target.get("status") != "pass":
        raise SystemExit(f"fuzz target did not pass: {name}")
    if target.get("runs_requested") != runs:
        raise SystemExit(f"fuzz run count mismatch: {name}")
    corpus = target.get("corpus")
    if (
        not isinstance(corpus, dict)
        or not isinstance(corpus.get("files"), int)
        or corpus["files"] < 0
        or not isinstance(corpus.get("bytes"), int)
        or corpus["bytes"] < 0
        or not isinstance(corpus.get("names"), list)
        or len(corpus["names"]) != corpus["files"]
    ):
        raise SystemExit(f"invalid corpus inventory: {name}")
    log_name = target.get("log")
    resource_name = target.get("resource_log")
    if log_name not in by_name or resource_name not in by_name:
        raise SystemExit(f"missing target logs: {name}")
    log_text = by_name[log_name].read_text(encoding="utf-8", errors="replace")
    resource_text = by_name[resource_name].read_text(
        encoding="utf-8", errors="replace"
    )
    if not (log_text + resource_text).strip():
        raise SystemExit(f"empty fuzz logs: {name}")
    progress = target.get("last_progress")
    if not isinstance(progress, str) or not re.search(r"#\d+", progress):
        raise SystemExit(f"fuzz log has no progress marker: {name}")
    rss = target.get("max_rss_kib")
    if rss is not None and (not isinstance(rss, int) or rss < 0):
        raise SystemExit(f"invalid RSS evidence: {name}")

print(f"fuzz report verified: {report_path}")
PY
