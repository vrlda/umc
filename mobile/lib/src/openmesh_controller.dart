import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'openmesh_platform.dart';

class OpenMeshController extends ChangeNotifier {
  OpenMeshController({required OpenMeshPlatform platform})
      : _platform = platform;

  final OpenMeshPlatform _platform;

  Timer? _pollTimer;
  bool _busy = false;
  String? _bannerMessage;
  OpenMeshSnapshot _snapshot = const OpenMeshSnapshot.initial();
  int _selectedHops = 2;
  final int _bandwidthMbps = 10;
  OpenMeshContributionMode _selectedMode = OpenMeshContributionMode.off;

  bool get busy => _busy;
  bool get connected => _snapshot.running;
  bool get relaySuspended => _snapshot.relaySuspended;
  int get selectedHops => _selectedHops;
  int get bandwidthMbps => _bandwidthMbps;
  OpenMeshContributionMode get selectedMode => _selectedMode;
  OpenMeshSnapshot get snapshot => _snapshot;
  String? get bannerMessage => _bannerMessage;

  Future<void> initialize() async {
    await refreshStatus();
    _pollTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) => unawaited(refreshStatus(silent: true)),
    );
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> refreshStatus({bool silent = false}) async {
    try {
      final latest = await _platform.status();
      _snapshot = latest;
      if (latest.running) {
        _selectedHops = latest.hops.clamp(1, 3);
        _selectedMode = _modeFromSnapshot(latest.mode);
      }
      if (!silent) {
        _bannerMessage = null;
      }
      notifyListeners();
    } on PlatformException catch (error) {
      if (!silent) {
        _bannerMessage =
            error.message ?? 'Unable to reach the Android VPN bridge.';
        notifyListeners();
      }
    }
  }

  Future<void> toggleConnection() async {
    if (_busy) {
      return;
    }

    _busy = true;
    notifyListeners();

    try {
      if (connected) {
        _snapshot = await _platform.stop();
        _bannerMessage = null;
      } else {
        final prepared = await _platform.prepareVpn();
        if (!prepared) {
          _bannerMessage =
              'Approve the VPN permission prompt, then tap connect again.';
          return;
        }

        _snapshot = await _platform.start(
          hops: _selectedHops,
          mode: _selectedMode,
          bandwidthMbps: _bandwidthMbps,
        );
        _bannerMessage = null;
      }
    } on PlatformException catch (error) {
      _bannerMessage = error.message ?? 'Unable to change VPN state.';
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  Future<void> selectHops(int hops) async {
    if (hops == _selectedHops) {
      return;
    }

    _selectedHops = hops.clamp(1, 3);
    notifyListeners();
    await _applyIfRunning();
  }

  Future<void> selectMode(OpenMeshContributionMode mode) async {
    if (mode == _selectedMode) {
      return;
    }

    _selectedMode = mode;
    notifyListeners();
    await _applyIfRunning();
  }

  Future<void> _applyIfRunning() async {
    if (!connected || _busy) {
      return;
    }

    _busy = true;
    notifyListeners();
    try {
      _snapshot = await _platform.start(
        hops: _selectedHops,
        mode: _selectedMode,
        bandwidthMbps: _bandwidthMbps,
      );
      _bannerMessage = null;
    } on PlatformException catch (error) {
      _bannerMessage = error.message ?? 'Unable to apply the new VPN settings.';
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  OpenMeshContributionMode _modeFromSnapshot(String mode) {
    switch (mode.toLowerCase()) {
      case 'relay':
        return OpenMeshContributionMode.relay;
      case 'exit':
      case 'full':
        return OpenMeshContributionMode.exit;
      default:
        return OpenMeshContributionMode.off;
    }
  }
}
