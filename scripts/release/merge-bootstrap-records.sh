#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  printf 'usage: %s <output-json> <self-record.json> [more self-record.json ...]\n' "$0" >&2
  exit 1
fi

OUTPUT_PATH="$1"
shift

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required to merge bootstrap records.\n' >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
jq -s 'map(select(type == "object" and (.id // "") != ""))' "$@" > "$OUTPUT_PATH"
printf 'bootstrap manifest written to %s\n' "$OUTPUT_PATH"
