#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_DIR" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
output_dir=$1
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v cargo-audit >/dev/null 2>&1 || {
    echo "cargo-audit is required; install it with: cargo install cargo-audit --locked" >&2
    exit 1
}

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "dependency audit requires a clean working tree" >&2
    echo "commit or otherwise remove tracked and untracked changes before running" >&2
    exit 1
fi

if [ -e "$output_dir" ]; then
    echo "output directory already exists: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"

cargo metadata --format-version 1 --locked >"$output_dir/sbom.json"
cargo tree --locked >"$output_dir/dependency-tree.txt"
# cargo-audit reads the pinned Cargo.lock; metadata --locked above guarantees
# that the SBOM and advisory scan refer to the same dependency graph.
cargo audit --json >"$output_dir/cargo-audit.json"
cp Cargo.lock "$output_dir/Cargo.lock"

export UMC_DEPENDENCY_OUTPUT="$output_dir"
export UMC_DEPENDENCY_LOCK_SHA256=$(python3 - <<'PY'
import hashlib
from pathlib import Path
print(hashlib.sha256(Path("Cargo.lock").read_bytes()).hexdigest())
PY
)
export UMC_DEPENDENCY_COMMIT=$(git rev-parse HEAD)
export UMC_DEPENDENCY_DIRTY=$(test -n "$(git status --porcelain)" && echo true || echo false)
export UMC_DEPENDENCY_AUDIT_VERSION=$(cargo-audit --version)
export UMC_DEPENDENCY_TREE=$(git rev-parse HEAD^{tree})

python3 - <<'PY'
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

output = Path(os.environ["UMC_DEPENDENCY_OUTPUT"])
sbom = json.loads((output / "sbom.json").read_text(encoding="utf-8"))
audit = json.loads((output / "cargo-audit.json").read_text(encoding="utf-8"))
vulnerabilities = audit.get("vulnerabilities", {}).get("list", [])
assert sbom.get("packages"), "SBOM contains no packages"
assert not vulnerabilities, f"cargo-audit found {len(vulnerabilities)} vulnerabilities"

artifacts = []
for path in sorted(output.iterdir()):
    if path.name == "dependency-report.json" or not path.is_file():
        continue
    artifacts.append({
        "name": path.name,
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    })

record = {
    "schema": "umc-dependency-audit-v1",
    "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "git_commit": os.environ["UMC_DEPENDENCY_COMMIT"],
    "git_tree": os.environ["UMC_DEPENDENCY_TREE"],
    "working_tree_dirty": os.environ["UMC_DEPENDENCY_DIRTY"] == "true",
    "lock_sha256": os.environ["UMC_DEPENDENCY_LOCK_SHA256"],
    "package_count": len(sbom["packages"]),
    "cargo_audit": os.environ["UMC_DEPENDENCY_AUDIT_VERSION"],
    "advisory_database": audit.get("database", {}),
    "vulnerabilities": 0,
    "artifacts": artifacts,
    "status": "pass",
}
(output / "dependency-report.json").write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(f"dependency audit: {output}")
PY
