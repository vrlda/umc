# Release Flow

OpenMesh release artifacts are published through GitHub Releases by
`.github/workflows/release.yml`.

## Published assets

- `openmesh-install.sh`
- `openmeshd-linux-amd64`
- `openmeshd-linux-arm64`
- `bootstrap-peers.json`
- `openmesh-desktop-macos-arm64.dmg`
- `openmesh-desktop-windows-x64.zip`
- `openmesh-android.apk`

Each binary artifact is accompanied by a `.sha256` file.

## Bootstrap manifest

Clients and fresh nodes discover the mesh through `bootstrap-peers.json`.

To update it:

1. Start one or more public seed nodes.
2. Run `openmeshd self-record` on each one.
3. Merge those JSON files into `bootstrap/peers.json`.
4. Tag and publish a new release.

Helper:

- `scripts/release/merge-bootstrap-records.sh bootstrap/peers.json seed-1.json seed-2.json`

## Linux installer

The release workflow renders `scripts/install.sh` into `openmesh-install.sh`
with the current `owner/repo` baked in. That installer downloads release assets
from GitHub, verifies checksums, writes `/etc/openmesh/config.json`, and points
fresh installs at `bootstrap-peers.json` on the latest release.
