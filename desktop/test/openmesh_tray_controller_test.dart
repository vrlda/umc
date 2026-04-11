import 'package:flutter_test/flutter_test.dart';
import 'package:openmesh_desktop/src/openmesh_config_store.dart';
import 'package:openmesh_desktop/src/openmesh_daemon_client.dart';
import 'package:openmesh_desktop/src/openmesh_models.dart';
import 'package:openmesh_desktop/src/openmesh_tray_controller.dart';

void main() {
  test(
    'toggleConnection starts the daemon with the saved relay settings',
    () async {
      final store = _MemoryConfigStore(
        const OpenMeshSettings(
          configPath: '/tmp/config.json',
          dataDir: '/tmp/openmesh',
          mode: OpenMeshContributionMode.relay,
          hops: 2,
          bandwidthMbps: 10,
        ),
      );
      final gateway = _FakeDaemonGateway();
      final controller = OpenMeshTrayController(
        gateway: gateway,
        configStore: store,
        pollInterval: const Duration(hours: 1),
      );

      await controller.initialize();
      await controller.toggleConnection();

      expect(controller.running, isTrue);
      expect(gateway.startCalls, 1);
      expect(gateway.lastStartedMode, OpenMeshContributionMode.relay);
      expect(gateway.lastStartedHops, 2);

      controller.dispose();
    },
  );

  test(
    'selectMode off stops a running daemon and keeps the menu in off state',
    () async {
      final store = _MemoryConfigStore(
        const OpenMeshSettings(
          configPath: '/tmp/config.json',
          dataDir: '/tmp/openmesh',
          mode: OpenMeshContributionMode.exit,
          hops: 3,
          bandwidthMbps: 10,
        ),
      );
      final gateway = _FakeDaemonGateway(
        snapshot: OpenMeshDaemonSnapshot(
          running: true,
          nodeId: 'node-1',
          mode: 'exit',
          startedAt: DateTime.parse('2026-04-10T00:00:00Z'),
          listenAddr: ':443',
          knownPeers: 7,
          bandwidthUsedBytes: 128,
          circuit: OpenMeshCircuitSnapshot(
            hops: 3,
            streams: 1,
            createdAt: DateTime.parse('2026-04-10T00:00:00Z'),
            path: const <String>['node-1', 'node-2', 'node-3'],
          ),
        ),
      );
      final controller = OpenMeshTrayController(
        gateway: gateway,
        configStore: store,
        pollInterval: const Duration(hours: 1),
      );

      await controller.initialize();
      await controller.selectMode(OpenMeshContributionMode.off);

      expect(controller.running, isFalse);
      expect(controller.selectedMode, OpenMeshContributionMode.off);
      expect(gateway.stopCalls, 1);

      controller.dispose();
    },
  );

  test('selectHops restarts a running daemon with the new hop count', () async {
    final store = _MemoryConfigStore(
      const OpenMeshSettings(
        configPath: '/tmp/config.json',
        dataDir: '/tmp/openmesh',
        mode: OpenMeshContributionMode.relay,
        hops: 2,
        bandwidthMbps: 10,
      ),
    );
    final gateway = _FakeDaemonGateway(
      snapshot: OpenMeshDaemonSnapshot(
        running: true,
        nodeId: 'node-1',
        mode: 'relay',
        startedAt: DateTime.parse('2026-04-10T00:00:00Z'),
        listenAddr: ':443',
        knownPeers: 4,
        bandwidthUsedBytes: 64,
        circuit: OpenMeshCircuitSnapshot(
          hops: 2,
          streams: 1,
          createdAt: DateTime.parse('2026-04-10T00:00:00Z'),
          path: const <String>['node-1', 'node-2'],
        ),
      ),
    );
    final controller = OpenMeshTrayController(
      gateway: gateway,
      configStore: store,
      pollInterval: const Duration(hours: 1),
    );

    await controller.initialize();
    await controller.selectHops(3);

    expect(controller.selectedHops, 3);
    expect(gateway.stopCalls, 1);
    expect(gateway.startCalls, 1);
    expect(gateway.lastStartedHops, 3);

    controller.dispose();
  });
}

class _MemoryConfigStore implements OpenMeshConfigStore {
  _MemoryConfigStore(this._settings);

  OpenMeshSettings _settings;

  @override
  Future<OpenMeshSettings> load() async => _settings;

  @override
  Future<OpenMeshSettings> save(OpenMeshSettings settings) async {
    _settings = settings;
    return _settings;
  }
}

class _FakeDaemonGateway implements OpenMeshDaemonGateway {
  _FakeDaemonGateway({OpenMeshDaemonSnapshot? snapshot})
    : _snapshot = snapshot ?? const OpenMeshDaemonSnapshot.offline();

  OpenMeshDaemonSnapshot _snapshot;
  int startCalls = 0;
  int stopCalls = 0;
  OpenMeshContributionMode? lastStartedMode;
  int? lastStartedHops;

  @override
  Future<List<OpenMeshPeer>> peers({
    required String configPath,
    required String dataDir,
  }) async {
    return const <OpenMeshPeer>[
      OpenMeshPeer(id: 'node-2', country: 'DE', exit: true),
      OpenMeshPeer(id: 'node-3', country: 'NL', exit: true),
    ];
  }

  @override
  Future<void> start({
    required String configPath,
    required String dataDir,
    required OpenMeshContributionMode mode,
    required int hops,
    required int bandwidthMbps,
  }) async {
    startCalls++;
    lastStartedMode = mode;
    lastStartedHops = hops;
    _snapshot = OpenMeshDaemonSnapshot(
      running: true,
      nodeId: 'node-1',
      mode: mode.daemonMode,
      startedAt: DateTime.parse('2026-04-10T00:00:00Z'),
      listenAddr: ':443',
      knownPeers: 6,
      bandwidthUsedBytes: 256,
      circuit: OpenMeshCircuitSnapshot(
        hops: hops,
        streams: 1,
        createdAt: DateTime.parse('2026-04-10T00:00:00Z'),
        path: hops == 3
            ? const <String>['node-1', 'node-2', 'node-3']
            : const <String>['node-1', 'node-2'],
      ),
    );
  }

  @override
  Future<OpenMeshDaemonSnapshot> status({
    required String configPath,
    required String dataDir,
  }) async {
    return _snapshot;
  }

  @override
  Future<void> stop({
    required String configPath,
    required String dataDir,
  }) async {
    stopCalls++;
    _snapshot = const OpenMeshDaemonSnapshot.offline();
  }
}
