#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_DIR [RUNS_PER_TARGET]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
output_dir=$1
runs=${2:-1000}

case "$runs" in
    ''|*[!0-9]*)
        echo "RUNS_PER_TARGET must be a non-negative integer" >&2
        exit 2
        ;;
esac

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v cargo-fuzz >/dev/null 2>&1 || {
    echo "cargo-fuzz is required (install with: cargo install cargo-fuzz --locked)" >&2
    exit 1
}
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "fuzz report requires a clean working tree" >&2
    echo "commit or otherwise remove tracked and untracked changes before running" >&2
    exit 1
fi

if [ -e "$output_dir" ]; then
    echo "output directory already exists: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)

targets=(
    wire_parser
    relay_frames
    handshake_encoding
    bundle_frame
    control_envelope
    carrier_framing
    session_packet
    identity_binding
    route_frames
    plugin_manifest
    db_recovery
    storage_recovery
)

time_args=(-l)
if /usr/bin/time -v true >/dev/null 2>&1; then
    time_args=(-v)
fi

for target in "${targets[@]}"; do
    log="$output_dir/$target.log"
    resource_log="$output_dir/$target-resource.txt"
    run_corpus=$(mktemp -d)
    cp -a "$repo_root/fuzz/corpus/$target/." "$run_corpus/"
    if ! (
        cd "$repo_root/fuzz"
        /usr/bin/time "${time_args[@]}" cargo fuzz run "$target" "$run_corpus" \
            --sanitizer none -- -runs="$runs" >"$log" 2>"$resource_log"
    ); then
        cat "$log" >&2
        cat "$resource_log" >&2
        rm -rf "$run_corpus"
        exit 1
    fi
    rm -rf "$run_corpus"
done

export UMC_FUZZ_OUTPUT="$output_dir"
export UMC_FUZZ_REPO="$repo_root"
export UMC_FUZZ_RUNS="$runs"
export UMC_FUZZ_TARGETS="${targets[*]}"

python3 - <<'PY'
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

output = Path(os.environ["UMC_FUZZ_OUTPUT"])
repo = Path(os.environ["UMC_FUZZ_REPO"])
targets = os.environ["UMC_FUZZ_TARGETS"].split()

def seed_inventory(target):
    corpus = repo / "fuzz" / "corpus" / target
    files = sorted(path for path in corpus.iterdir() if path.is_file())
    return {
        "files": len(files),
        "bytes": sum(path.stat().st_size for path in files),
        "names": [path.name for path in files],
    }

def max_rss_kib(text):
    byte_matches = re.findall(
        r"(?m)^\s*(\d+)\s+maximum resident set size\s*$", text, re.IGNORECASE
    )
    if byte_matches:
        return (int(byte_matches[-1]) + 1023) // 1024
    kib_matches = re.findall(r"Maximum resident set size \(kbytes\):\s+(\d+)", text)
    return int(kib_matches[-1]) if kib_matches else None

target_reports = []
for target in targets:
    log_text = (output / f"{target}.log").read_text(encoding="utf-8", errors="replace")
    resource_text = (output / f"{target}-resource.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    progress = [
        line.strip()
        for line in (log_text + "\n" + resource_text).splitlines()
        if re.search(r"#\d+.*(?:DONE|INIT)", line)
    ]
    target_reports.append(
        {
            "name": target,
            "runs_requested": int(os.environ["UMC_FUZZ_RUNS"]),
            "status": "pass",
            "corpus": seed_inventory(target),
            "last_progress": progress[-1] if progress else None,
            "max_rss_kib": max_rss_kib(resource_text),
            "log": f"{target}.log",
            "resource_log": f"{target}-resource.txt",
        }
    )

commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
tree = subprocess.check_output(
    ["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True
).strip()
dirty = bool(
    subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
        text=True,
    ).strip()
)
artifacts = []
for path in sorted(output.iterdir()):
    if not path.is_file():
        continue
    artifacts.append(
        {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    )

record = {
    "schema": "umc-fuzz-report-v1",
    "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "git_commit": commit,
    "git_tree": tree,
    "working_tree_dirty": dirty,
    "status": "pass",
    "runs_per_target": int(os.environ["UMC_FUZZ_RUNS"]),
    "targets": target_reports,
    "artifacts": artifacts,
}
(output / "fuzz-report.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY

echo "fuzz report: $output_dir"
