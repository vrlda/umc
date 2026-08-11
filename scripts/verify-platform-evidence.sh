#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 EVIDENCE_JSON" >&2
    exit 2
fi

command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required" >&2
    exit 1
}

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

python3 - "$1" <<'PY'
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    record = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read platform evidence: {exc}") from exc

if record.get("schema") != "umc-platform-evidence-v1":
    raise SystemExit("unsupported platform evidence schema")
if record.get("working_tree_dirty") is not False:
    raise SystemExit("platform evidence was not captured from a clean tree")
commit = record.get("git_commit")
if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
    raise SystemExit("invalid platform evidence commit")
actual_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
if actual_commit != commit:
    raise SystemExit("platform evidence commit does not match the checkout")
if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], text=True):
    raise SystemExit("checkout is dirty; evidence is not reproducible")

host = record.get("host", {})
target = host.get("rust_target")
if not isinstance(target, str) or not target:
    raise SystemExit("missing host rust target")
verification = record.get("verification", {})
if verification.get("workspace_tests") != "pass" or verification.get("release_build") != "pass":
    raise SystemExit("platform verification did not pass")

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

lock_digest = verification.get("cargo_lock_sha256")
if lock_digest != sha256(Path("Cargo.lock")):
    raise SystemExit("Cargo.lock digest mismatch")
binary = verification.get("release_binary", {})
binary_path = binary.get("path")
if not isinstance(binary_path, str) or Path(binary_path).name != "umcd":
    raise SystemExit("invalid release binary path")
binary_file = Path(binary_path)
if not binary_file.is_file():
    raise SystemExit(f"release binary is missing: {binary_file}")
if binary.get("sha256") != sha256(binary_file):
    raise SystemExit("release binary digest mismatch")

print(f"platform evidence verified: {path}")
PY
