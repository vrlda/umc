#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 MANIFEST TRUSTED_PUBLIC_KEY_DIR" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
manifest=$1
trusted_dir=$2

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
[ -f "$manifest" ] || { echo "manifest not found: $manifest" >&2; exit 1; }
[ -d "$trusted_dir" ] || { echo "trusted key directory not found: $trusted_dir" >&2; exit 1; }

python3 - "$manifest" "$trusted_dir" "$(dirname "$0")/verify-release-manifest.sh" <<'PY'
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1]).resolve()
trusted_dir = Path(sys.argv[2]).resolve()
verify_script = Path(sys.argv[3]).resolve()

try:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid manifest: {error}")

signing = document.get("signing")
if not isinstance(signing, dict):
    raise SystemExit("manifest signing object is required")
threshold = signing.get("threshold")
signatures = signing.get("signatures")
if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold != 1:
    raise SystemExit("solo v0.1 release policy requires signing.threshold=1")
if not isinstance(signatures, list) or len(signatures) != 1:
    raise SystemExit("solo v0.1 release policy requires exactly one signature")

key_id_pattern = re.compile(r"^[0-9a-f]{64}$")
seen = set()
valid = []
manifest_dir = manifest_path.parent

for entry in signatures:
    if not isinstance(entry, dict):
        raise SystemExit("each signing signature must be an object")
    key_id = entry.get("key_id")
    filename = entry.get("file")
    if not isinstance(key_id, str) or not key_id_pattern.fullmatch(key_id):
        raise SystemExit("signature key_id must be a lowercase SHA-256 hex digest")
    if key_id in seen:
        raise SystemExit(f"duplicate signer: {key_id}")
    seen.add(key_id)
    if not isinstance(filename, str) or not filename or Path(filename).is_absolute():
        raise SystemExit("signature file must be a relative path")
    signature_path = (manifest_dir / filename).resolve()
    try:
        signature_path.relative_to(manifest_dir)
    except ValueError:
        raise SystemExit(f"signature escapes manifest directory: {filename}")
    key_path = (trusted_dir / f"{key_id}.pem").resolve()
    try:
        key_path.relative_to(trusted_dir)
    except ValueError:
        raise SystemExit("trusted key path escapes key directory")
    if not key_path.is_file():
        raise SystemExit(f"trusted public key is missing: {key_id}")
    actual_key_id = hashlib.sha256(key_path.read_bytes()).hexdigest()
    if actual_key_id != key_id:
        raise SystemExit(f"trusted public key hash does not match key_id: {key_id}")
    if not signature_path.is_file():
        raise SystemExit(f"signature file is missing: {filename}")
    result = subprocess.run(
        [str(verify_script), str(manifest_path), str(key_path), str(signature_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode == 0:
        valid.append(key_id)

if len(valid) != 1:
    raise SystemExit("release signature is invalid")

print(json.dumps({
    "schema": "umc-release-signature-verification-v1",
    "policy": "solo-1-of-1",
    "manifest": str(manifest_path),
    "threshold": threshold,
    "declared_signers": len(signatures),
    "valid_signers": valid,
    "status": "pass",
}, sort_keys=True))
PY
