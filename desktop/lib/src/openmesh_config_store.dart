import 'dart:convert';
import 'dart:io';

import 'openmesh_models.dart';
import 'openmesh_paths.dart';

abstract class OpenMeshConfigStore {
  Future<OpenMeshSettings> load();

  Future<OpenMeshSettings> save(OpenMeshSettings settings);
}

class FileOpenMeshConfigStore implements OpenMeshConfigStore {
  const FileOpenMeshConfigStore();

  static const _encoder = JsonEncoder.withIndent('  ');
  static const _bootstrapManifestUrls = String.fromEnvironment(
    'OPENMESH_BOOTSTRAP_MANIFEST_URLS',
  );

  @override
  Future<OpenMeshSettings> load() async {
    final configPath = OpenMeshPaths.defaultConfigPath();
    final configFile = File(configPath);

    Map<String, dynamic> document = <String, dynamic>{};
    if (await configFile.exists()) {
      final raw = await configFile.readAsString();
      if (raw.trim().isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          document = Map<String, dynamic>.from(decoded);
        }
      }
    }

    final dataDir = OpenMeshPaths.expandUserPath(
      _readString(document, 'data_dir') ?? '~/.openmesh',
    );
    final settings = OpenMeshSettings(
      configPath: configPath,
      dataDir: dataDir,
      mode: _modeFromString(_readString(document, 'mode')),
      hops: _readInt(document, 'hops')?.clamp(1, 3) ?? 2,
      bandwidthMbps: _readInt(document, 'bandwidth_limit_mbps') ?? 10,
    );

    if (!await configFile.exists()) {
      return save(settings);
    }
    return settings;
  }

  @override
  Future<OpenMeshSettings> save(OpenMeshSettings settings) async {
    final configFile = File(settings.configPath);
    Map<String, dynamic> document = <String, dynamic>{};

    if (await configFile.exists()) {
      final raw = await configFile.readAsString();
      if (raw.trim().isNotEmpty) {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          document = Map<String, dynamic>.from(decoded);
        }
      }
    }

    document['mode'] = settings.mode == OpenMeshContributionMode.off
        ? OpenMeshContributionMode.relay.daemonMode
        : settings.mode.daemonMode;
    document['hops'] = settings.hops.clamp(1, 3);
    document['bandwidth_limit_mbps'] = settings.bandwidthMbps;
    document['data_dir'] = settings.dataDir;
    document['log_level'] = _readString(document, 'log_level') ?? 'warn';
    document['exit_policy'] = _normalizedExitPolicy(document['exit_policy']);
    document['bootstrap_manifest_urls'] = _normalizedBootstrapManifestURLs(
      document['bootstrap_manifest_urls'],
    );

    await configFile.parent.create(recursive: true);
    await configFile.writeAsString('${_encoder.convert(document)}\n');
    return settings;
  }

  static String? _readString(Map<String, dynamic> document, String key) {
    final value = document[key];
    if (value is String && value.isNotEmpty) {
      return value;
    }
    return null;
  }

  static int? _readInt(Map<String, dynamic> document, String key) {
    final value = document[key];
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return null;
  }

  static OpenMeshContributionMode _modeFromString(String? value) {
    switch ((value ?? '').trim().toLowerCase()) {
      case 'relay':
        return OpenMeshContributionMode.relay;
      case 'exit':
      case 'full':
        return OpenMeshContributionMode.exit;
      default:
        return OpenMeshContributionMode.relay;
    }
  }

  static Map<String, dynamic> _normalizedExitPolicy(Object? current) {
    if (current case final Map<dynamic, dynamic> policy) {
      final normalized = Map<String, dynamic>.from(
        policy.map((key, value) => MapEntry('$key', value)),
      );
      normalized['ports'] = _normalizedPorts(normalized['ports']);
      normalized['blocklist'] =
          normalized['blocklist'] is String &&
              (normalized['blocklist'] as String).trim().isNotEmpty
          ? normalized['blocklist']
          : 'default';
      return normalized;
    }

    return <String, dynamic>{
      'ports': <int>[443],
      'blocklist': 'default',
    };
  }

  static List<int> _normalizedPorts(Object? ports) {
    if (ports case final List<dynamic> values) {
      final result = <int>[];
      for (final value in values) {
        if (value is int) {
          result.add(value);
          continue;
        }
        if (value is num) {
          result.add(value.toInt());
        }
      }
      if (result.isNotEmpty) {
        return result;
      }
    }
    return <int>[443];
  }

  static List<String> _normalizedBootstrapManifestURLs(Object? current) {
    final values = <String>[];
    if (current case final List<dynamic> urls) {
      for (final value in urls) {
        if (value is String && value.trim().isNotEmpty) {
          values.add(value.trim());
        }
      }
    }

    if (values.isEmpty && _bootstrapManifestUrls.trim().isNotEmpty) {
      for (final value in _bootstrapManifestUrls.split(',')) {
        final trimmed = value.trim();
        if (trimmed.isNotEmpty) {
          values.add(trimmed);
        }
      }
    }

    final deduped = <String>[];
    final seen = <String>{};
    for (final value in values) {
      if (seen.add(value)) {
        deduped.add(value);
      }
    }
    return deduped;
  }
}
