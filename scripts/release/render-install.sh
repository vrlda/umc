#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  printf 'usage: %s <github-owner/repo> <output-path>\n' "$0" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE_FILE="$ROOT_DIR/scripts/install.sh"
REPOSITORY="$1"
OUTPUT_PATH="$2"

mkdir -p "$(dirname "$OUTPUT_PATH")"
sed "s|__OPENMESH_GITHUB_REPOSITORY__|$REPOSITORY|g" "$SOURCE_FILE" > "$OUTPUT_PATH"
chmod +x "$OUTPUT_PATH"
