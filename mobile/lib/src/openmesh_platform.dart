import 'dart:async';

import 'package:flutter/services.dart';

enum OpenMeshContributionMode { off, relay, exit }

extension OpenMeshContributionModeX on OpenMeshContributionMode {
  String get label => switch (this) {
        OpenMeshContributionMode.off => 'Off',
        OpenMeshContributionMode.relay => 'Relay',
        OpenMeshContributionMode.exit => 'Exit',
      };

  String get engineMode => switch (this) {
        OpenMeshContributionMode.off => 'off',
        OpenMeshContributionMode.relay => 'relay',
        OpenMeshContributionMode.exit => 'exit',
      };
}

class OpenMeshSnapshot {
  const OpenMeshSnapshot({
    required this.running,
    required this.relaySuspended,
    required this.bytesIn,
    required this.bytesOut,
    required this.nodeId,
    required this.mode,
    required this.hops,
    required this.statusJson,
  });

  const OpenMeshSnapshot.initial()
      : running = false,
        relaySuspended = false,
        bytesIn = 0,
        bytesOut = 0,
        nodeId = '',
        mode = 'off',
        hops = 2,
        statusJson = '{}';

  final bool running;
  final bool relaySuspended;
  final int bytesIn;
  final int bytesOut;
  final String nodeId;
  final String mode;
  final int hops;
  final String statusJson;

  factory OpenMeshSnapshot.fromMap(Map<Object?, Object?> map) {
    int readInt(String key, int fallback) {
      final value = map[key];
      if (value is int) {
        return value;
      }
      if (value is num) {
        return value.toInt();
      }
      return fallback;
    }

    String readString(String key, String fallback) {
      final value = map[key];
      if (value is String && value.isNotEmpty) {
        return value;
      }
      return fallback;
    }

    bool readBool(String key, bool fallback) {
      final value = map[key];
      if (value is bool) {
        return value;
      }
      return fallback;
    }

    return OpenMeshSnapshot(
      running: readBool('running', false),
      relaySuspended: readBool('relaySuspended', false),
      bytesIn: readInt('bytesIn', 0),
      bytesOut: readInt('bytesOut', 0),
      nodeId: readString('nodeId', ''),
      mode: readString('mode', 'off'),
      hops: readInt('hops', 2),
      statusJson: readString('statusJson', '{}'),
    );
  }
}

abstract class OpenMeshPlatform {
  const OpenMeshPlatform();

  Future<bool> prepareVpn();

  Future<OpenMeshSnapshot> start({
    required int hops,
    required OpenMeshContributionMode mode,
    required int bandwidthMbps,
  });

  Future<OpenMeshSnapshot> stop();

  Future<OpenMeshSnapshot> status();
}

class MethodChannelOpenMeshPlatform extends OpenMeshPlatform {
  const MethodChannelOpenMeshPlatform({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(_channelName);

  static const String _channelName = 'openmesh/vpn';

  final MethodChannel _channel;

  @override
  Future<bool> prepareVpn() async {
    final result = await _channel.invokeMethod<bool>('prepareVpn');
    return result ?? false;
  }

  @override
  Future<OpenMeshSnapshot> start({
    required int hops,
    required OpenMeshContributionMode mode,
    required int bandwidthMbps,
  }) async {
    final result = await _channel.invokeMethod<Object?>(
      'start',
      <String, Object>{
        'hops': hops,
        'mode': mode.engineMode,
        'bandwidthMbps': bandwidthMbps,
      },
    );
    return _snapshotFromResult(result);
  }

  @override
  Future<OpenMeshSnapshot> stop() async {
    final result = await _channel.invokeMethod<Object?>('stop');
    return _snapshotFromResult(result);
  }

  @override
  Future<OpenMeshSnapshot> status() async {
    final result = await _channel.invokeMethod<Object?>('status');
    return _snapshotFromResult(result);
  }

  OpenMeshSnapshot _snapshotFromResult(Object? result) {
    if (result case final Map<Object?, Object?> map) {
      return OpenMeshSnapshot.fromMap(map);
    }
    return const OpenMeshSnapshot.initial();
  }
}
