"""Run the published deterministic parser campaign and write CI evidence.

This is a bounded stable-Rust regression campaign, not a claim of sanitizer or
third-party audit coverage. The development-only cargo-fuzz corpus remains
local; this gate records the parser inputs and counts shipped in the tests.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


MARKER = "FUZZ_EVIDENCE schema=umc-fuzz-evidence-v1 target=wire_parser"


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def run(output: Path) -> Dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    dirty = bool(git_value(repo, "status", "--porcelain", "--untracked-files=all"))
    command = [
        "cargo", "test", "--package", "umc-wire", "--test", "fuzz_smoke",
        "--locked", "--", "--nocapture",
    ]
    result = subprocess.run(command, cwd=repo, check=False, capture_output=True, text=True)
    output_text = result.stdout + result.stderr
    markers = [line for line in output_text.splitlines() if MARKER in line]
    values: Dict[str, int] = {}
    for key in ("seeds", "random_cases", "max_input_bytes", "corpus_edges", "hostile_inputs"):
        matches = re.findall(rf"\b{key}=(\d+)", output_text)
        if matches:
            values[key] = int(matches[-1])
    expected = {
        "seeds": 4,
        "random_cases": 100_000,
        "max_input_bytes": 299,
        "corpus_edges": 10,
        "hostile_inputs": 7,
    }
    campaign_pass = values == expected and len(markers) == 3
    record: Dict[str, Any] = {
        "schema": "umc-fuzz-report-v1",
        "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_commit": git_value(repo, "rev-parse", "HEAD"),
        "git_tree": git_value(repo, "rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": dirty,
        "status": "pass" if result.returncode == 0 and not dirty and campaign_pass else "fail",
        "scope": "bounded deterministic stable-Rust parser campaign",
        "command": command,
        "returncode": result.returncode,
        "campaign": {"target": "wire_parser", **values},
        "markers": markers,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    record["report_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    print(json.dumps(record, indent=2, sort_keys=True))
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record = run(args.output)
    return 0 if record["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
