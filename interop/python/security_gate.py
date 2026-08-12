"""Small, reproducible security-evidence gate for the published repository.

This is an implementation regression gate, not a claim of independent audit.
It deliberately uses argv-based subprocesses and records the exact checkout,
commands, and results in a JSON artifact suitable for CI retention.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def command_result(repo: Path, name: str, command: List[str]) -> Dict[str, Any]:
    result = subprocess.run(command, cwd=repo, check=False)
    return {
        "name": name,
        "command": command,
        "returncode": result.returncode,
        "status": "pass" if result.returncode == 0 else "fail",
    }


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def static_checks(repo: Path) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    policy = (repo / "SECURITY.md").read_text(encoding="utf-8")
    expected_link = "https://github.com/vrlda/umc/security/advisories/new"
    checks.append(
        {
            "name": "published security reporting link",
            "status": "pass" if expected_link in policy else "fail",
        }
    )
    tracked = git_value(repo, "ls-files").splitlines()
    forbidden = (
        'Command::new("sh")',
        'Command::new("bash")',
        '.arg("-c")',
        "eval ",
    )
    matches = []
    for relative in tracked:
        if not relative.endswith((".rs", ".sh")):
            continue
        text = (repo / relative).read_text(encoding="utf-8", errors="replace")
        for marker in forbidden:
            if marker in text:
                matches.append({"file": relative, "marker": marker})
    checks.append(
        {
            "name": "no shell construction in tracked Rust or shell code",
            "status": "pass" if not matches else "fail",
            "matches": matches,
        }
    )
    checks.append(
        {
            "name": "published independent peer present",
            "status": "pass"
            if (repo / "interop/python/live_runner.py").is_file()
            else "fail",
        }
    )
    return checks


def run(output: Path) -> Dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    dirty = bool(git_value(repo, "status", "--porcelain", "--untracked-files=all"))
    checks = static_checks(repo)
    commands = [
        (
            "workspace regression suite",
            ["cargo", "test", "--workspace", "--locked"],
        ),
        (
            "wire fuzz smoke regressions",
            ["cargo", "test", "--package", "umc-wire", "--test", "fuzz_smoke", "--locked"],
        ),
        (
            "handshake tamper regressions",
            [
                "cargo",
                "test",
                "--package",
                "umc-handshake",
                "--test",
                "finished_exchange",
                "--locked",
            ],
        ),
        (
            "keystore corruption regressions",
            ["cargo", "test", "--package", "umc-storage", "--lib", "keystore", "--locked"],
        ),
        (
            "emergency protocol disablement",
            [
                "cargo",
                "test",
                "--package",
                "umcd",
                "emergency_disablement_blocks_protocol_crypto_and_carrier",
                "--locked",
            ],
        ),
        (
            "public relay containment",
            [
                "cargo",
                "test",
                "--package",
                "umcd",
                "emergency_public_relay_disablement_refuses_public_opens",
                "--locked",
            ],
        ),
    ]
    results = [command_result(repo, name, command) for name, command in commands]
    all_checks = checks + results
    record: Dict[str, Any] = {
        "schema": "umc-security-evidence-v1",
        "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_commit": git_value(repo, "rev-parse", "HEAD"),
        "git_tree": git_value(repo, "rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": dirty,
        "status": "pass"
        if not dirty and all(item["status"] == "pass" for item in all_checks)
        else "fail",
        "checks": all_checks,
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
