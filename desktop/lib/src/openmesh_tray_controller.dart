import 'dart:async';

import 'package:flutter/foundation.dart';

import 'openmesh_config_store.dart';
import 'openmesh_daemon_client.dart';
import 'openmesh_models.dart';

class OpenMeshTrayController extends ChangeNotifier {
  OpenMeshTrayController({
    required OpenMeshDaemonGateway gateway,
    OpenMeshConfigStore? configStore,
    Duration? pollInterval,
  }) : _gateway = gateway,
       _configStore = configStore ?? const FileOpenMeshConfigStore(),
       _pollInterval = pollInterval ?? const Duration(seconds: 2);

  final OpenMeshDaemonGateway _gateway;
  final OpenMeshConfigStore _configStore;
  final Duration _pollInterval;

  Timer? _pollTimer;
  bool _busy = false;
  String? _notice;
  OpenMeshSettings? _settings;
  OpenMeshDaemonSnapshot _snapshot = const OpenMeshDaemonSnapshot.offline();
  OpenMeshContributionMode _selectedMode = OpenMeshContributionMode.relay;
  OpenMeshContributionMode _lastConnectableMode =
      OpenMeshContributionMode.relay;
  int _selectedHops = 2;
  String? _exitCountry;
  String? _resolvedExitPeerID;

  bool get busy => _busy;
  bool get running => _snapshot.running;
  String? get notice => _notice;
  OpenMeshDaemonSnapshot get snapshot => _snapshot;
  OpenMeshContributionMode get selectedMode => _selectedMode;
  int get selectedHops => _selectedHops;

  String get connectionLabel {
    if (_busy) {
      return 'Working...';
    }
    if (!running) {
      return 'Disconnected';
    }
    if (_exitCountry != null && _exitCountry!.trim().isNotEmpty) {
      return 'Connected (${_exitCountry!.trim()} -> exit)';
    }
    return 'Connected';
  }

  String get trayTooltip {
    if (running) {
      return 'OpenMesh is connected in ${selectedMode.label.toLowerCase()} mode';
    }
    return 'OpenMesh is offline';
  }

  String get hopsMenuLabel => 'Hops: $_selectedHops';

  String get modeMenuLabel => 'Mode: ${_selectedMode.label}';

  String get nodeID => _snapshot.nodeId;

  String get modeDescription =>
      running ? _humanMode(_snapshot.mode) : _selectedMode.label;

  String? get startedAtLabel =>
      _snapshot.startedAt?.toLocal().toIso8601String().replaceFirst('T', ' ');

  Future<void> initialize() async {
    final loaded = await _configStore.load();
    _settings = loaded;
    _selectedMode = loaded.mode;
    _selectedHops = loaded.hops.clamp(1, 3);
    if (_selectedMode.isConnectable) {
      _lastConnectableMode = _selectedMode;
    }

    await refreshStatus();
    _pollTimer = Timer.periodic(
      _pollInterval,
      (_) => unawaited(refreshStatus(silent: true)),
    );
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> refreshStatus({bool silent = false}) async {
    final settings = _requireSettings();
    try {
      final snapshot = await _gateway.status(
        configPath: settings.configPath,
        dataDir: settings.dataDir,
      );
      _snapshot = snapshot;
      if (snapshot.running) {
        _selectedMode = _modeFromDaemon(snapshot.mode);
        if (_selectedMode.isConnectable) {
          _lastConnectableMode = _selectedMode;
        }
        final circuit = snapshot.circuit;
        if (circuit != null) {
          _selectedHops = circuit.hops.clamp(1, 3);
        }
        await _refreshExitCountry(settings, snapshot);
      } else {
        _exitCountry = null;
        _resolvedExitPeerID = null;
      }
      if (!silent) {
        _notice = null;
      }
    } on OpenMeshDaemonException catch (error) {
      _notice = error.message;
    }
    notifyListeners();
  }

  Future<void> toggleConnection() async {
    if (_busy) {
      return;
    }

    _busy = true;
    notifyListeners();
    try {
      if (running) {
        await _stopDaemon();
      } else {
        final connectMode = _selectedMode.isConnectable
            ? _selectedMode
            : _lastConnectableMode;
        _selectedMode = connectMode;
        await _persistSettings();
        await _startDaemon(connectMode);
      }
      _notice = null;
    } on OpenMeshDaemonException catch (error) {
      _notice = error.message;
    } finally {
      _busy = false;
      await refreshStatus(silent: _notice == null);
    }
  }

  Future<void> selectHops(int hops) async {
    final normalized = hops.clamp(1, 3);
    if (normalized == _selectedHops) {
      return;
    }

    _selectedHops = normalized;
    await _persistSettings();
    notifyListeners();

    if (running) {
      await _restartWithCurrentSettings();
    }
  }

  Future<void> selectMode(OpenMeshContributionMode mode) async {
    if (mode == _selectedMode) {
      return;
    }

    _selectedMode = mode;
    if (mode.isConnectable) {
      _lastConnectableMode = mode;
    }
    await _persistSettings();
    notifyListeners();

    if (mode == OpenMeshContributionMode.off) {
      if (running) {
        await _stopDaemon();
        await refreshStatus();
      }
      return;
    }

    if (running) {
      await _restartWithCurrentSettings();
    }
  }

  String formatBandwidth(int bytes) {
    const units = <String>['B', 'KB', 'MB', 'GB'];
    var value = bytes.toDouble();
    var unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    final digits = unit == 0 ? 0 : 1;
    return '${value.toStringAsFixed(digits)} ${units[unit]}';
  }

  Future<void> _restartWithCurrentSettings() async {
    if (_busy) {
      return;
    }

    _busy = true;
    notifyListeners();
    try {
      await _stopDaemon();
      await _startDaemon(_selectedMode);
      _notice = null;
    } on OpenMeshDaemonException catch (error) {
      _notice = error.message;
    } finally {
      _busy = false;
      await refreshStatus(silent: _notice == null);
    }
  }

  Future<void> _startDaemon(OpenMeshContributionMode mode) async {
    final settings = _requireSettings();
    await _gateway.start(
      configPath: settings.configPath,
      dataDir: settings.dataDir,
      mode: mode,
      hops: _selectedHops,
      bandwidthMbps: settings.bandwidthMbps,
    );
  }

  Future<void> _stopDaemon() async {
    final settings = _requireSettings();
    await _gateway.stop(
      configPath: settings.configPath,
      dataDir: settings.dataDir,
    );
  }

  Future<void> _persistSettings() async {
    final current = _requireSettings();
    _settings = await _configStore.save(
      current.copyWith(
        hops: _selectedHops,
        mode: _selectedMode.isConnectable
            ? _selectedMode
            : _lastConnectableMode,
      ),
    );
  }

  Future<void> _refreshExitCountry(
    OpenMeshSettings settings,
    OpenMeshDaemonSnapshot snapshot,
  ) async {
    final circuit = snapshot.circuit;
    if (circuit == null || circuit.path.isEmpty) {
      _exitCountry = null;
      _resolvedExitPeerID = null;
      return;
    }

    final exitPeerID = circuit.path.last;
    if (exitPeerID == _resolvedExitPeerID) {
      return;
    }

    final peers = await _gateway.peers(
      configPath: settings.configPath,
      dataDir: settings.dataDir,
    );
    OpenMeshPeer? peer;
    for (final candidate in peers) {
      if (candidate.id == exitPeerID) {
        peer = candidate;
        break;
      }
    }
    _resolvedExitPeerID = exitPeerID;
    _exitCountry = peer?.country;
  }

  OpenMeshSettings _requireSettings() {
    final settings = _settings;
    if (settings == null) {
      throw const OpenMeshDaemonException(
        'OpenMesh settings are not initialized yet.',
      );
    }
    return settings;
  }

  OpenMeshContributionMode _modeFromDaemon(String mode) {
    switch (mode.trim().toLowerCase()) {
      case 'relay':
        return OpenMeshContributionMode.relay;
      case 'exit':
      case 'full':
        return OpenMeshContributionMode.exit;
      default:
        return OpenMeshContributionMode.off;
    }
  }

  String _humanMode(String mode) {
    return _modeFromDaemon(mode).label;
  }
}
