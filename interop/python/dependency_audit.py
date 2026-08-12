"""Generate a locked Cargo SBOM and RustSec audit evidence report."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def run_command(repo: Path, command: List[str], output: Path) -> None:
    with output.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=repo, check=False, stdout=stream, stderr=subprocess.PIPE, text=True)
    output.with_name(output.name + ".stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(output: Path) -> Dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    if git_value(repo, "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("dependency audit requires a clean working tree")
    output.mkdir(parents=True, exist_ok=False)
    sbom = output / "sbom.json"
    tree = output / "dependency-tree.txt"
    audit = output / "cargo-audit.json"
    run_command(repo, ["cargo", "metadata", "--format-version", "1", "--locked"], sbom)
    run_command(repo, ["cargo", "tree", "--locked"], tree)
    run_command(repo, ["cargo", "audit", "--json"], audit)
    lock_copy = output / "Cargo.lock"
    lock_copy.write_bytes((repo / "Cargo.lock").read_bytes())
    metadata = json.loads(sbom.read_text(encoding="utf-8"))
    audit_record = json.loads(audit.read_text(encoding="utf-8"))
    vulnerabilities = audit_record.get("vulnerabilities", {}).get("list", [])
    packages = metadata.get("packages", [])
    if not packages:
        raise SystemExit("SBOM contains no packages")
    if vulnerabilities:
        raise SystemExit(f"cargo-audit found {len(vulnerabilities)} vulnerabilities")
    artifacts = []
    for path in sorted(output.iterdir()):
        if path.name == "dependency-report.json":
            continue
        artifacts.append({"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)})
    record: Dict[str, Any] = {
        "schema": "umc-dependency-audit-v1",
        "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_commit": git_value(repo, "rev-parse", "HEAD"),
        "git_tree": git_value(repo, "rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": False,
        "lock_sha256": digest(repo / "Cargo.lock"),
        "package_count": len(packages),
        "cargo_audit": subprocess.check_output(["cargo", "audit", "--version"], cwd=repo, text=True).strip(),
        "advisory_database": audit_record.get("database", {}),
        "vulnerabilities": len(vulnerabilities),
        "artifacts": artifacts,
        "status": "pass",
    }
    report = output / "dependency-report.json"
    report.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
