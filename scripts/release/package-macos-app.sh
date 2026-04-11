#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  printf 'usage: %s <app-path> <openmeshd-path> <artifact-name> <output-dir>\n' "$0" >&2
  exit 1
fi

APP_PATH="$1"
DAEMON_PATH="$2"
ARTIFACT_NAME="$3"
OUTPUT_DIR="$4"

if [ ! -d "$APP_PATH" ]; then
  printf 'app bundle not found: %s\n' "$APP_PATH" >&2
  exit 1
fi
if [ ! -f "$DAEMON_PATH" ]; then
  printf 'daemon binary not found: %s\n' "$DAEMON_PATH" >&2
  exit 1
fi

RESOURCE_DIR="$APP_PATH/Contents/Resources/openmesh"
mkdir -p "$RESOURCE_DIR"
install -m 0755 "$DAEMON_PATH" "$RESOURCE_DIR/openmeshd"

mkdir -p "$OUTPUT_DIR"
DMG_PATH="$OUTPUT_DIR/$ARTIFACT_NAME"
hdiutil create \
  -volname "OpenMesh" \
  -srcfolder "$APP_PATH" \
  -ov \
  -format UDZO \
  "$DMG_PATH" >/dev/null

printf '%s\n' "$DMG_PATH"
