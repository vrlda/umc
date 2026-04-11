enum OpenMeshContributionMode { off, relay, exit }

extension OpenMeshContributionModeX on OpenMeshContributionMode {
  String get label => switch (this) {
    OpenMeshContributionMode.off => 'Off',
    OpenMeshContributionMode.relay => 'Relay',
    OpenMeshContributionMode.exit => 'Exit',
  };

  String get daemonMode => switch (this) {
    OpenMeshContributionMode.off => 'off',
    OpenMeshContributionMode.relay => 'relay',
    OpenMeshContributionMode.exit => 'exit',
  };

  bool get isConnectable => this != OpenMeshContributionMode.off;
}

class OpenMeshSettings {
  const OpenMeshSettings({
    required this.configPath,
    required this.dataDir,
    required this.mode,
    required this.hops,
    required this.bandwidthMbps,
  });

  final String configPath;
  final String dataDir;
  final OpenMeshContributionMode mode;
  final int hops;
  final int bandwidthMbps;

  OpenMeshSettings copyWith({
    String? configPath,
    String? dataDir,
    OpenMeshContributionMode? mode,
    int? hops,
    int? bandwidthMbps,
  }) {
    return OpenMeshSettings(
      configPath: configPath ?? this.configPath,
      dataDir: dataDir ?? this.dataDir,
      mode: mode ?? this.mode,
      hops: hops ?? this.hops,
      bandwidthMbps: bandwidthMbps ?? this.bandwidthMbps,
    );
  }
}

class OpenMeshCircuitSnapshot {
  const OpenMeshCircuitSnapshot({
    required this.hops,
    required this.streams,
    required this.createdAt,
    required this.path,
  });

  final int hops;
  final int streams;
  final DateTime createdAt;
  final List<String> path;
}

class OpenMeshDaemonSnapshot {
  const OpenMeshDaemonSnapshot({
    required this.running,
    required this.nodeId,
    required this.mode,
    required this.startedAt,
    required this.listenAddr,
    required this.knownPeers,
    required this.bandwidthUsedBytes,
    required this.circuit,
  });

  const OpenMeshDaemonSnapshot.offline()
    : running = false,
      nodeId = '',
      mode = 'off',
      startedAt = null,
      listenAddr = '',
      knownPeers = 0,
      bandwidthUsedBytes = 0,
      circuit = null;

  final bool running;
  final String nodeId;
  final String mode;
  final DateTime? startedAt;
  final String listenAddr;
  final int knownPeers;
  final int bandwidthUsedBytes;
  final OpenMeshCircuitSnapshot? circuit;
}

class OpenMeshPeer {
  const OpenMeshPeer({
    required this.id,
    required this.country,
    required this.exit,
  });

  final String id;
  final String country;
  final bool exit;
}
