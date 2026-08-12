"""Produce reproducible benchmark and encrypted session soak evidence."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def run_command(repo: Path, command: List[str], output: Path, env: Optional[Dict[str, str]] = None) -> None:
    with output.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=repo, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(command)}; see {output}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(output: Path, duration_ms: int) -> Dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    if git_value(repo, "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("release baseline requires a clean working tree")
    output.mkdir(parents=True, exist_ok=False)
    benchmarks = [("umc-wire", "wire"), ("umc-crypto", "crypto"), ("umc-session", "session")]
    for package, bench in benchmarks:
        run_command(
            repo,
            ["cargo", "bench", "--locked", "--package", package, "--bench", bench, "--", "--noplot"],
            output / f"{bench}-benchmark.txt",
        )
    env = os.environ.copy()
    env["UMC_SOAK_DURATION_MS"] = str(duration_ms)
    run_command(
        repo,
        [
            "cargo", "test", "--locked", "--package", "umc-session", "--test", "release_soak",
            "encrypted_stream_datagram_release_soak", "--", "--ignored", "--nocapture",
        ],
        output / "soak.txt",
        env,
    )
    soak_text = (output / "soak.txt").read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r"RELEASE_BASELINE schema=umc-resource-trend-v1 iterations=(\d+) "
        r"stream_bytes=(\d+) datagram_bytes=(\d+) elapsed_ms=(\d+) "
        r"peak_queued=(\d+) queue_capacity=(\d+)",
        soak_text,
    )
    if match is None:
        raise SystemExit("soak output is missing its resource trend marker")
    trend = {
        "schema": "umc-resource-trend-v1",
        "iterations": int(match.group(1)),
        "stream_bytes": int(match.group(2)),
        "datagram_bytes": int(match.group(3)),
        "elapsed_ms": int(match.group(4)),
        "peak_queued_packets": int(match.group(5)),
        "queue_capacity_packets": int(match.group(6)),
    }
    if trend["iterations"] <= 0 or trend["elapsed_ms"] < duration_ms:
        raise SystemExit("invalid soak duration or iteration evidence")
    if trend["peak_queued_packets"] > trend["queue_capacity_packets"]:
        raise SystemExit("soak exceeded its queue capacity")
    trend["queue_headroom_packets"] = trend["queue_capacity_packets"] - trend["peak_queued_packets"]
    (output / "resource-trend.json").write_text(json.dumps(trend, indent=2) + "\n", encoding="utf-8")
    artifacts = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            artifacts.append({"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)})
    rustc = subprocess.check_output(["rustc", "-vV"], cwd=repo, text=True)
    target = next(line.split(": ", 1)[1] for line in rustc.splitlines() if line.startswith("host: "))
    record = {
        "schema": "umc-release-baseline-v1",
        "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git_commit": git_value(repo, "rev-parse", "HEAD"),
        "git_tree": git_value(repo, "rev-parse", "HEAD^{tree}"),
        "working_tree_dirty": False,
        "host": {"os": os.uname().sysname, "architecture": os.uname().machine, "kernel": os.uname().release, "rust_target": target},
        "toolchain": {"cargo": subprocess.check_output(["cargo", "-V"], cwd=repo, text=True).strip(), "rustc": rustc},
        "benchmarks": [f"{package}/{bench}" for package, bench in benchmarks],
        "soak": {"test": "umc-session::encrypted_stream_datagram_release_soak", "duration_ms": duration_ms, "status": "pass", "resource_trend": trend},
        "cargo_lock_sha256": digest(repo / "Cargo.lock"),
        "artifacts": artifacts,
    }
    (output / "baseline.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-ms", type=int, default=600_000)
    args = parser.parse_args()
    if args.duration_ms <= 0:
        parser.error("--duration-ms must be positive")
    run(args.output, args.duration_ms)
    return 0


if __name__ == "__main__":
    sys.exit(main())
