#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_JSON" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
output=$1

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v rustc >/dev/null 2>&1 || { echo "rustc is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    echo "platform evidence requires a clean working tree" >&2
    exit 1
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/umc-platform-evidence.XXXXXX")
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

rustc_info=$(rustc -vV)
cargo_version=$(cargo -V)
target=$(printf '%s\n' "$rustc_info" | awk '$1 == "host:" { print $2 }')
[ -n "$target" ] || { echo "rustc host target is missing" >&2; exit 1; }

test_log="$tmp_dir/cargo-test.log"
build_log="$tmp_dir/cargo-build.log"

if ! cargo test --workspace --locked >"$test_log" 2>&1; then
    cat "$test_log" >&2
    exit 1
fi

if ! cargo build --package umcd --release --locked >"$build_log" 2>&1; then
    cat "$build_log" >&2
    exit 1
fi

binary="target/release/umcd"
[ -f "$binary" ] || { echo "release binary missing: $binary" >&2; exit 1; }

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

git_commit=$(git rev-parse HEAD)
git_dirty=false
if [ -n "$(git status --porcelain)" ]; then
    git_dirty=true
fi

export UMC_EVIDENCE_OUTPUT="$output"
export UMC_EVIDENCE_TARGET="$target"
export UMC_EVIDENCE_RUSTC_INFO="$rustc_info"
export UMC_EVIDENCE_CARGO_VERSION="$cargo_version"
export UMC_EVIDENCE_OS=$(uname -s)
export UMC_EVIDENCE_ARCH=$(uname -m)
export UMC_EVIDENCE_KERNEL=$(uname -r)
export UMC_EVIDENCE_COMMIT="$git_commit"
export UMC_EVIDENCE_DIRTY="$git_dirty"
export UMC_EVIDENCE_BINARY="$binary"
export UMC_EVIDENCE_BINARY_SHA256=$(sha256_file "$binary")
export UMC_EVIDENCE_LOCK_SHA256=$(sha256_file Cargo.lock)

mkdir -p "$(dirname "$output")"
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

output = Path(os.environ["UMC_EVIDENCE_OUTPUT"])
rustc_info = os.environ["UMC_EVIDENCE_RUSTC_INFO"]
record = {
    "schema": "umc-platform-evidence-v1",
    "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "git_commit": os.environ["UMC_EVIDENCE_COMMIT"],
    "working_tree_dirty": os.environ["UMC_EVIDENCE_DIRTY"] == "true",
    "host": {
        "os": os.environ["UMC_EVIDENCE_OS"],
        "architecture": os.environ["UMC_EVIDENCE_ARCH"],
        "kernel": os.environ["UMC_EVIDENCE_KERNEL"],
        "rust_target": os.environ["UMC_EVIDENCE_TARGET"],
    },
    "toolchain": {
        "cargo": os.environ["UMC_EVIDENCE_CARGO_VERSION"],
        "rustc": rustc_info,
    },
    "verification": {
        "workspace_tests": "pass",
        "release_build": "pass",
        "cargo_lock_sha256": os.environ["UMC_EVIDENCE_LOCK_SHA256"],
        "release_binary": {
            "path": os.environ["UMC_EVIDENCE_BINARY"],
            "sha256": os.environ["UMC_EVIDENCE_BINARY_SHA256"],
        },
    },
}
output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY

echo "platform evidence: $output"
