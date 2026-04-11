import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;

import 'openmesh_models.dart';

class OpenMeshDaemonException implements Exception {
  const OpenMeshDaemonException(this.message);

  final String message;

  @override
  String toString() => message;
}

abstract class OpenMeshDaemonGateway {
  Future<void> start({
    required String configPath,
    required String dataDir,
    required OpenMeshContributionMode mode,
    required int hops,
    required int bandwidthMbps,
  });

  Future<OpenMeshDaemonSnapshot> status({
    required String configPath,
    required String dataDir,
  });

  Future<List<OpenMeshPeer>> peers({
    required String configPath,
    required String dataDir,
  });

  Future<void> stop({required String configPath, required String dataDir});
}

class ShellingOpenMeshDaemonGateway implements OpenMeshDaemonGateway {
  ShellingOpenMeshDaemonGateway({
    String? binaryPath,
    Duration? startupTimeout,
    Duration? shutdownTimeout,
  }) : _binaryPath =
           binaryPath ??
           Platform.environment['OPENMESHD_BIN'] ??
           _resolveBundledBinaryPath() ??
           'openmeshd',
       _startupTimeout = startupTimeout ?? const Duration(seconds: 6),
       _shutdownTimeout = shutdownTimeout ?? const Duration(seconds: 4);

  final String _binaryPath;
  final Duration _startupTimeout;
  final Duration _shutdownTimeout;

  static String? _resolveBundledBinaryPath() {
    final executablePath = File(Platform.resolvedExecutable).absolute.path;
    final executableDir = File(executablePath).parent.path;
    final candidates = <String>[
      if (Platform.isMacOS)
        path.normalize(
          path.join(executableDir, '..', 'Resources', 'openmesh', 'openmeshd'),
        ),
      if (Platform.isWindows) path.join(executableDir, 'openmeshd.exe'),
      if (Platform.isLinux) path.join(executableDir, 'openmeshd'),
      if (Platform.isLinux)
        path.normalize(
          path.join(executableDir, '..', 'lib', 'openmesh', 'openmeshd'),
        ),
    ];

    for (final candidate in candidates) {
      if (File(candidate).existsSync()) {
        return candidate;
      }
    }
    return null;
  }

  @override
  Future<void> start({
    required String configPath,
    required String dataDir,
    required OpenMeshContributionMode mode,
    required int hops,
    required int bandwidthMbps,
  }) async {
    final daemonMode = mode.isConnectable
        ? mode.daemonMode
        : OpenMeshContributionMode.relay.daemonMode;
    final args = <String>[
      '--config',
      configPath,
      'start',
      '--mode',
      daemonMode,
      '--hops',
      '${hops.clamp(1, 3)}',
      '--bandwidth',
      '$bandwidthMbps',
    ];
    if (Platform.isMacOS) {
      args.add('--utun');
    }

    try {
      await Process.start(_binaryPath, args, mode: ProcessStartMode.detached);
    } on ProcessException catch (error) {
      throw OpenMeshDaemonException(
        'Unable to launch openmeshd. Set OPENMESHD_BIN or add it to PATH. ${error.message}',
      );
    }

    await _waitForRunning(
      configPath: configPath,
      dataDir: dataDir,
      timeout: _startupTimeout,
    );
  }

  @override
  Future<OpenMeshDaemonSnapshot> status({
    required String configPath,
    required String dataDir,
  }) async {
    if (Platform.isWindows) {
      return _statusViaCli(configPath);
    }

    try {
      final payload = await _sendUnixIpc(dataDir: dataDir, command: 'status');
      final status = payload['status'];
      if (status is! Map) {
        return const OpenMeshDaemonSnapshot.offline();
      }
      return _snapshotFromJson(Map<String, dynamic>.from(status));
    } on SocketException {
      return const OpenMeshDaemonSnapshot.offline();
    }
  }

  @override
  Future<List<OpenMeshPeer>> peers({
    required String configPath,
    required String dataDir,
  }) async {
    if (Platform.isWindows) {
      return const <OpenMeshPeer>[];
    }

    try {
      final payload = await _sendUnixIpc(dataDir: dataDir, command: 'peers');
      final peers = payload['peers'];
      if (peers is! List<dynamic>) {
        return const <OpenMeshPeer>[];
      }
      return peers
          .whereType<Map>()
          .map((peer) {
            final map = Map<String, dynamic>.from(peer);
            return OpenMeshPeer(
              id: _readString(map, 'id'),
              country: _readString(map, 'country'),
              exit: _readBool(map, 'exit'),
            );
          })
          .toList(growable: false);
    } on SocketException {
      return const <OpenMeshPeer>[];
    }
  }

  @override
  Future<void> stop({
    required String configPath,
    required String dataDir,
  }) async {
    if (Platform.isWindows) {
      final result = await _runCli(configPath, 'stop');
      if (result.exitCode != 0 &&
          !result.combinedOutput.toLowerCase().contains(
            'daemon is not running',
          )) {
        throw OpenMeshDaemonException(result.combinedOutput.trim());
      }
      await _waitForStopped(
        configPath: configPath,
        dataDir: dataDir,
        timeout: _shutdownTimeout,
      );
      return;
    }

    try {
      await _sendUnixIpc(dataDir: dataDir, command: 'stop');
    } on SocketException {
      return;
    }
    await _waitForStopped(
      configPath: configPath,
      dataDir: dataDir,
      timeout: _shutdownTimeout,
    );
  }

  Future<void> _waitForRunning({
    required String configPath,
    required String dataDir,
    required Duration timeout,
  }) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      final snapshot = await status(configPath: configPath, dataDir: dataDir);
      if (snapshot.running) {
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }

    throw const OpenMeshDaemonException(
      'openmeshd did not become ready before the startup timeout elapsed.',
    );
  }

  Future<void> _waitForStopped({
    required String configPath,
    required String dataDir,
    required Duration timeout,
  }) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      final snapshot = await status(configPath: configPath, dataDir: dataDir);
      if (!snapshot.running) {
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
  }

  Future<OpenMeshDaemonSnapshot> _statusViaCli(String configPath) async {
    final result = await _runCli(configPath, 'status');
    if (result.exitCode != 0) {
      if (result.combinedOutput.toLowerCase().contains(
        'daemon is not running',
      )) {
        return const OpenMeshDaemonSnapshot.offline();
      }
      throw OpenMeshDaemonException(result.combinedOutput.trim());
    }

    final lines = LineSplitter.split(result.stdout).toList(growable: false);
    if (lines.isEmpty) {
      return const OpenMeshDaemonSnapshot.offline();
    }

    String nodeId = '';
    String mode = 'off';
    DateTime? startedAt;
    String listenAddr = '';
    int knownPeers = 0;
    int bandwidthUsedBytes = 0;
    OpenMeshCircuitSnapshot? circuit;

    for (final line in lines) {
      if (line.startsWith('Node ID: ')) {
        nodeId = line.substring('Node ID: '.length).trim();
      } else if (line.startsWith('Mode: ')) {
        mode = line.substring('Mode: '.length).trim();
      } else if (line.startsWith('Started: ')) {
        startedAt = DateTime.tryParse(
          line.substring('Started: '.length).trim(),
        );
      } else if (line.startsWith('Listen: ')) {
        listenAddr = line.substring('Listen: '.length).trim();
      } else if (line.startsWith('Known peers: ')) {
        knownPeers =
            int.tryParse(line.substring('Known peers: '.length).trim()) ?? 0;
      } else if (line.startsWith('Bandwidth used: ')) {
        final rawValue = line
            .substring('Bandwidth used: '.length)
            .replaceAll(' bytes', '')
            .trim();
        bandwidthUsedBytes = int.tryParse(rawValue) ?? 0;
      } else if (line.startsWith('Circuit: ') && !line.contains('inactive')) {
        circuit = _parseCircuitLine(line);
      } else if (line.startsWith('Path: ') && circuit != null) {
        circuit = OpenMeshCircuitSnapshot(
          hops: circuit.hops,
          streams: circuit.streams,
          createdAt: circuit.createdAt,
          path: line.substring('Path: '.length).split(' -> '),
        );
      }
    }

    if (nodeId.isEmpty) {
      return const OpenMeshDaemonSnapshot.offline();
    }

    return OpenMeshDaemonSnapshot(
      running: true,
      nodeId: nodeId,
      mode: mode,
      startedAt: startedAt,
      listenAddr: listenAddr,
      knownPeers: knownPeers,
      bandwidthUsedBytes: bandwidthUsedBytes,
      circuit: circuit,
    );
  }

  OpenMeshCircuitSnapshot? _parseCircuitLine(String line) {
    final value = line.substring('Circuit: '.length).trim();
    final parts = value.split(',');
    if (parts.length < 3) {
      return null;
    }

    final hops = int.tryParse(parts[0].replaceAll(' hops', '').trim()) ?? 0;
    final streams =
        int.tryParse(parts[1].replaceAll(' streams', '').trim()) ?? 0;
    final createdAt = DateTime.tryParse(
      parts[2].replaceFirst('created', '').trim(),
    );
    if (hops <= 0 || streams < 0 || createdAt == null) {
      return null;
    }

    return OpenMeshCircuitSnapshot(
      hops: hops,
      streams: streams,
      createdAt: createdAt,
      path: const <String>[],
    );
  }

  Future<Map<String, dynamic>> _sendUnixIpc({
    required String dataDir,
    required String command,
  }) async {
    final endpoint = _unixIpcEndpoint(dataDir);
    final address = InternetAddress(endpoint, type: InternetAddressType.unix);
    final socket = await Socket.connect(
      address,
      0,
      timeout: const Duration(milliseconds: 750),
    );

    try {
      socket.write(jsonEncode(<String, dynamic>{'command': command}));
      socket.write('\n');
      await socket.flush();

      final response = await utf8.decoder.bind(socket).join();
      if (response.trim().isEmpty) {
        return <String, dynamic>{};
      }

      final decoded = jsonDecode(response);
      if (decoded is! Map) {
        throw const OpenMeshDaemonException(
          'openmeshd returned an invalid IPC payload.',
        );
      }
      final payload = Map<String, dynamic>.from(decoded);
      if (_readString(payload, 'error').isNotEmpty) {
        throw OpenMeshDaemonException(_readString(payload, 'error'));
      }
      return payload;
    } finally {
      await socket.close();
    }
  }

  Future<_CliResult> _runCli(String configPath, String command) async {
    try {
      final result = await Process.run(_binaryPath, <String>[
        '--config',
        configPath,
        command,
      ]);
      return _CliResult(
        exitCode: result.exitCode,
        stdout: '${result.stdout}',
        stderr: '${result.stderr}',
      );
    } on ProcessException catch (error) {
      throw OpenMeshDaemonException(
        'Unable to launch openmeshd. Set OPENMESHD_BIN or add it to PATH. ${error.message}',
      );
    }
  }

  String _unixIpcEndpoint(String dataDir) {
    final override = Platform.environment['OPENMESH_IPC_PATH'];
    if (override != null && override.trim().isNotEmpty) {
      return override.trim();
    }

    final base = path.join(dataDir, 'openmeshd.sock');
    if (base.length <= 100) {
      return base;
    }

    final digest = sha256
        .convert(utf8.encode(base))
        .toString()
        .substring(0, 16);
    return path.join(Directory.systemTemp.path, 'openmeshd-$digest.sock');
  }

  OpenMeshDaemonSnapshot _snapshotFromJson(Map<String, dynamic> json) {
    final circuitJson = json['circuit'];
    OpenMeshCircuitSnapshot? circuit;
    if (circuitJson is Map) {
      final map = Map<String, dynamic>.from(circuitJson);
      circuit = OpenMeshCircuitSnapshot(
        hops: _readInt(map, 'hops'),
        streams: _readInt(map, 'streams'),
        createdAt:
            DateTime.tryParse(_readString(map, 'created_at')) ??
            DateTime.fromMillisecondsSinceEpoch(0),
        path: _readStringList(map, 'path'),
      );
    }

    return OpenMeshDaemonSnapshot(
      running: true,
      nodeId: _readString(json, 'node_id'),
      mode: _readString(json, 'mode'),
      startedAt: DateTime.tryParse(_readString(json, 'started_at')),
      listenAddr: _readString(json, 'listen_addr'),
      knownPeers: _readInt(json, 'known_peers'),
      bandwidthUsedBytes: _readInt(json, 'bandwidth_used_bytes'),
      circuit: circuit,
    );
  }

  static bool _readBool(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is bool) {
      return value;
    }
    return false;
  }

  static int _readInt(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return 0;
  }

  static String _readString(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is String) {
      return value;
    }
    return '';
  }

  static List<String> _readStringList(Map<String, dynamic> json, String key) {
    final value = json[key];
    if (value is! List<dynamic>) {
      return const <String>[];
    }
    return value.map((item) => '$item').toList(growable: false);
  }
}

class _CliResult {
  const _CliResult({
    required this.exitCode,
    required this.stdout,
    required this.stderr,
  });

  final int exitCode;
  final String stdout;
  final String stderr;

  String get combinedOutput {
    final stdoutText = stdout.trim();
    final stderrText = stderr.trim();
    if (stdoutText.isEmpty) {
      return stderrText;
    }
    if (stderrText.isEmpty) {
      return stdoutText;
    }
    return '$stdoutText\n$stderrText';
  }
}
