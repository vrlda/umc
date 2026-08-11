#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 DEPENDENCY_REPORT_JSON" >&2
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

report_path = Path(sys.argv[1])
try:
    record = json.loads(report_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read dependency report: {exc}") from exc

if record.get("schema") != "umc-dependency-audit-v1":
    raise SystemExit("unsupported dependency audit schema")
if record.get("working_tree_dirty") is not False:
    raise SystemExit("dependency evidence was not captured from a clean working tree")
for field in ("git_commit", "git_tree"):
    value = record.get(field)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit(f"invalid {field} in dependency report")
lock_digest = record.get("lock_sha256")
if not isinstance(lock_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", lock_digest):
    raise SystemExit("invalid Cargo.lock digest in dependency report")
if record.get("status") != "pass" or record.get("vulnerabilities") != 0:
    raise SystemExit("dependency audit did not pass with zero vulnerabilities")
if not isinstance(record.get("package_count"), int) or record["package_count"] <= 0:
    raise SystemExit("dependency report has no packages")

root = report_path.parent.resolve()
artifacts = record.get("artifacts")
if not isinstance(artifacts, list) or not artifacts:
    raise SystemExit("dependency report has no artifact digest records")
by_name = {}
for artifact in artifacts:
    name = artifact.get("name")
    if not isinstance(name, str) or Path(name).name != name:
        raise SystemExit("dependency artifact path escapes the report directory")
    if name in by_name:
        raise SystemExit(f"duplicate dependency artifact: {name}")
    path = root / name
    if not path.is_file():
        raise SystemExit(f"missing dependency artifact: {name}")
    content = path.read_bytes()
    if artifact.get("bytes") != len(content):
        raise SystemExit(f"dependency artifact size mismatch: {name}")
    digest = hashlib.sha256(content).hexdigest()
    if artifact.get("sha256") != digest:
        raise SystemExit(f"dependency artifact digest mismatch: {name}")
    by_name[name] = path

required = {"Cargo.lock", "sbom.json", "dependency-tree.txt", "cargo-audit.json"}
missing = required.difference(by_name)
if missing:
    raise SystemExit(f"dependency report is missing artifacts: {', '.join(sorted(missing))}")

if hashlib.sha256(by_name["Cargo.lock"].read_bytes()).hexdigest() != lock_digest:
    raise SystemExit("Cargo.lock digest does not match dependency report")
try:
    sbom = json.loads(by_name["sbom.json"].read_text(encoding="utf-8"))
    audit = json.loads(by_name["cargo-audit.json"].read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid dependency evidence JSON: {exc}") from exc

packages = sbom.get("packages")
if not isinstance(packages, list) or len(packages) != record["package_count"]:
    raise SystemExit("SBOM package count does not match dependency report")
vulnerabilities = audit.get("vulnerabilities", {}).get("list", [])
if not isinstance(vulnerabilities, list) or vulnerabilities:
    raise SystemExit("cargo-audit evidence contains vulnerabilities")

print(f"dependency audit verified: {report_path}")
PY
