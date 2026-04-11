# Android Integration

This directory contains the Android-side glue for Task 12:

- `build-openmesh-aar.sh` builds `openmeshmobile.aar` with `gomobile bind`
- `app/src/main/kotlin/net/openmesh/mobile/OpenMeshVpnService.kt` hosts the VPN service
- `app/src/main/kotlin/net/openmesh/mobile/OpenMeshMethodChannel.kt` exposes start/stop/status to Flutter
- `app/src/main/kotlin/net/openmesh/mobile/OpenMeshCoreBridge.kt` loads the gomobile AAR via reflection

Expected flow:

1. Build the Go bridge:
   `./build-openmesh-aar.sh`
2. Place the generated AAR in `app/libs/openmeshmobile.aar`
3. Build the APK with `flutter build apk --release`

The Kotlin sources intentionally keep the Go AAR dependency behind reflection so the Android code can be checked into the repo before the AAR is generated locally.
