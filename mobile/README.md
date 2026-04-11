# OpenMesh Mobile

This Flutter project builds the Android OpenMesh client.

## Release build

1. Build the Go bridge AAR:
   `bash android/build-openmesh-aar.sh`
2. Build the APK:
   `flutter build apk --release`

If you want the APK to discover seed peers on first launch, provide:

- `OPENMESH_BOOTSTRAP_MANIFEST_URLS=https://github.com/<owner>/<repo>/releases/latest/download/bootstrap-peers.json`

when building the APK. The Android app passes that value into the gomobile
engine before startup.

`gomobile bind` requires an Android SDK to be installed and discoverable
through the normal Android tooling environment.

## Android integration

- `android/app/src/main/kotlin/net/openmesh/mobile/OpenMeshVpnService.kt` hosts the VPN service
- `android/app/src/main/kotlin/net/openmesh/mobile/OpenMeshMethodChannel.kt` exposes start/stop/status to Flutter
- `android/app/src/main/kotlin/net/openmesh/mobile/OpenMeshCoreBridge.kt` loads the gomobile AAR via reflection
