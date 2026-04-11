import 'package:flutter_test/flutter_test.dart';
import 'package:openmesh_mobile/src/openmesh_app.dart';
import 'package:openmesh_mobile/src/openmesh_platform.dart';

void main() {
  testWidgets(
    'renders single-screen controls and starts VPN with selected state',
    (tester) async {
      final platform = FakeOpenMeshPlatform();

      await tester.pumpWidget(OpenMeshApp(platform: platform));
      await tester.pumpAndSettle();

      expect(find.text('OpenMesh'), findsOneWidget);
      expect(find.text('Connect'), findsOneWidget);
      expect(find.text('1 hop'), findsOneWidget);
      expect(find.text('2 hops'), findsOneWidget);
      expect(find.text('3 hops'), findsOneWidget);
      expect(find.text('Relay'), findsOneWidget);
      expect(find.text('Exit'), findsOneWidget);
      expect(find.text('Off'), findsOneWidget);

      await tester.tap(find.text('3 hops'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Relay'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Relay'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Connect'));
      await tester.pumpAndSettle();

      expect(platform.prepareCalled, isTrue);
      expect(platform.lastStartedHops, 3);
      expect(platform.lastStartedMode, OpenMeshContributionMode.relay);
      expect(find.text('Disconnect'), findsOneWidget);
    },
  );
}

class FakeOpenMeshPlatform extends OpenMeshPlatform {
  bool prepareCalled = false;
  int? lastStartedHops;
  OpenMeshContributionMode? lastStartedMode;
  OpenMeshSnapshot _snapshot = const OpenMeshSnapshot.initial();

  @override
  Future<bool> prepareVpn() async {
    prepareCalled = true;
    return true;
  }

  @override
  Future<OpenMeshSnapshot> start({
    required int hops,
    required OpenMeshContributionMode mode,
    required int bandwidthMbps,
  }) async {
    lastStartedHops = hops;
    lastStartedMode = mode;
    _snapshot = OpenMeshSnapshot(
      running: true,
      relaySuspended: false,
      bytesIn: 1024,
      bytesOut: 2048,
      nodeId: 'abcdef1234567890',
      mode: mode.engineMode,
      hops: hops,
      statusJson: '{}',
    );
    return _snapshot;
  }

  @override
  Future<OpenMeshSnapshot> status() async => _snapshot;

  @override
  Future<OpenMeshSnapshot> stop() async {
    _snapshot = const OpenMeshSnapshot.initial();
    return _snapshot;
  }
}
