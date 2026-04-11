import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'src/openmesh_daemon_client.dart';
import 'src/openmesh_desktop_app.dart';
import 'src/openmesh_tray_controller.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  const windowOptions = WindowOptions(
    size: Size(430, 540),
    center: true,
    backgroundColor: Color(0xFFF4F7F2),
    skipTaskbar: true,
    title: 'OpenMesh Status',
  );

  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.setPreventClose(true);
    await windowManager.setSkipTaskbar(true);
    await windowManager.hide();
  });

  final controller = OpenMeshTrayController(
    gateway: ShellingOpenMeshDaemonGateway(),
  );

  runApp(OpenMeshDesktopApp(controller: controller));
}
