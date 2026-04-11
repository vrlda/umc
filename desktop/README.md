# OpenMesh Desktop

This Flutter app is the desktop tray controller for OpenMesh.

## Packaging

The GitHub release workflow builds desktop downloads for:

- macOS: `openmesh-desktop-macos-arm64.dmg`
- Windows: `openmesh-desktop-windows-x64.zip`

Both packaged desktop builds are expected to carry a bundled `openmeshd`
binary. At runtime the app prefers that bundled daemon before falling back to
`OPENMESHD_BIN` or the system `PATH`.

## Local development

1. Run `flutter pub get` in `desktop/`
2. Make sure `openmeshd` is either on `PATH` or exported as `OPENMESHD_BIN`
3. Run `flutter run -d macos`, `flutter run -d windows`, or `flutter run -d linux`

For release builds, pass:

- `--dart-define=OPENMESH_BOOTSTRAP_MANIFEST_URLS=https://github.com/<owner>/<repo>/releases/latest/download/bootstrap-peers.json`

so first-launch configs know where to fetch seed peers.
