#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORE_DIR="$ROOT_DIR/core"
OUT_DIR="$ROOT_DIR/mobile/android/app/libs"
OUT_FILE="$OUT_DIR/openmeshmobile.aar"

mkdir -p "$OUT_DIR"

if ! command -v gomobile >/dev/null 2>&1; then
  printf 'gomobile is required. Install it with:\n  go install golang.org/x/mobile/cmd/gomobile@latest\n' >&2
  exit 1
fi

pushd "$CORE_DIR" >/dev/null
gomobile init
gomobile bind \
  -target=android \
  -androidapi 26 \
  -o "$OUT_FILE" \
  github.com/openmesh/core/mobile
popd >/dev/null

printf 'gomobile AAR written to %s\n' "$OUT_FILE"
