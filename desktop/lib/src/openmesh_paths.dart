import 'dart:io';

import 'package:path/path.dart' as path;

class OpenMeshPaths {
  OpenMeshPaths._();

  static String homeDirectory() {
    final environment = Platform.environment;
    final home = Platform.isWindows
        ? environment['USERPROFILE']
        : environment['HOME'];
    if (home != null && home.isNotEmpty) {
      return home;
    }
    return Directory.current.path;
  }

  static String expandUserPath(String value) {
    if (value == '~') {
      return homeDirectory();
    }
    if (value.startsWith('~/')) {
      return path.join(homeDirectory(), value.substring(2));
    }
    return value;
  }

  static String defaultDataDir() => path.join(homeDirectory(), '.openmesh');

  static String defaultConfigPath() =>
      path.join(defaultDataDir(), 'config.json');
}
