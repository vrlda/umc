import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'openmesh_models.dart';
import 'openmesh_tray_controller.dart';

class OpenMeshDesktopApp extends StatefulWidget {
  const OpenMeshDesktopApp({super.key, required this.controller});

  final OpenMeshTrayController controller;

  @override
  State<OpenMeshDesktopApp> createState() => _OpenMeshDesktopAppState();
}

class _OpenMeshDesktopAppState extends State<OpenMeshDesktopApp>
    with TrayListener, WindowListener {
  @override
  void initState() {
    super.initState();
    trayManager.addListener(this);
    windowManager.addListener(this);
    widget.controller.addListener(_handleControllerChanged);
    unawaited(_bootstrap());
  }

  @override
  void dispose() {
    trayManager.removeListener(this);
    windowManager.removeListener(this);
    widget.controller.removeListener(_handleControllerChanged);
    widget.controller.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    await _setTrayIcon();
    await widget.controller.initialize();
    await _syncTray();
  }

  Future<void> _setTrayIcon() {
    final iconPath = Platform.isWindows
        ? 'assets/tray/openmesh.ico'
        : 'assets/tray/openmesh.png';
    return trayManager.setIcon(iconPath);
  }

  Future<void> _syncTray() async {
    if (!mounted) {
      return;
    }
    await trayManager.setToolTip(widget.controller.trayTooltip);
    await trayManager.setContextMenu(_buildMenu());
  }

  Menu _buildMenu() {
    final controller = widget.controller;
    return Menu(
      items: <MenuItem>[
        MenuItem(label: controller.connectionLabel, disabled: true),
        MenuItem.separator(),
        MenuItem.submenu(
          label: controller.hopsMenuLabel,
          submenu: Menu(
            items: <MenuItem>[
              for (final hops in <int>[1, 2, 3])
                MenuItem.checkbox(
                  label: '$hops hop${hops == 1 ? '' : 's'}',
                  checked: controller.selectedHops == hops,
                  disabled: controller.busy,
                  onClick: (_) => unawaited(controller.selectHops(hops)),
                ),
            ],
          ),
        ),
        MenuItem.submenu(
          label: controller.modeMenuLabel,
          submenu: Menu(
            items: <MenuItem>[
              for (final mode in OpenMeshContributionMode.values)
                MenuItem.checkbox(
                  label: mode.label,
                  checked: controller.selectedMode == mode,
                  disabled: controller.busy,
                  onClick: (_) => unawaited(controller.selectMode(mode)),
                ),
            ],
          ),
        ),
        MenuItem.separator(),
        MenuItem(
          label: 'Status...',
          onClick: (_) => unawaited(_showStatusWindow()),
        ),
        MenuItem(label: 'Quit', onClick: (_) => unawaited(_quit())),
      ],
    );
  }

  Future<void> _showStatusWindow() async {
    await widget.controller.refreshStatus();
    if (!mounted) {
      return;
    }
    await windowManager.show();
    await windowManager.focus();
  }

  Future<void> _quit() async {
    await trayManager.destroy();
    await windowManager.destroy();
    exit(0);
  }

  void _handleControllerChanged() {
    if (mounted) {
      setState(() {});
    }
    unawaited(_syncTray());
  }

  @override
  void onTrayIconMouseDown() {
    unawaited(widget.controller.toggleConnection());
  }

  @override
  void onTrayIconRightMouseDown() {
    unawaited(trayManager.popUpContextMenu());
  }

  @override
  void onWindowClose() {
    unawaited(windowManager.hide());
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'OpenMesh',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1E6B5A),
          brightness: Brightness.light,
        ),
        scaffoldBackgroundColor: const Color(0xFFF4F7F2),
      ),
      home: _StatusWindow(controller: widget.controller),
    );
  }
}

class _StatusWindow extends StatelessWidget {
  const _StatusWindow({required this.controller});

  final OpenMeshTrayController controller;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final circuit = controller.snapshot.circuit;

    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenMesh Status'),
        actions: <Widget>[
          IconButton(
            tooltip: 'Refresh',
            onPressed: controller.busy
                ? null
                : () => unawaited(controller.refreshStatus()),
            icon: const Icon(Icons.refresh_rounded),
          ),
          IconButton(
            tooltip: 'Hide',
            onPressed: () => unawaited(windowManager.hide()),
            icon: const Icon(Icons.close_rounded),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: <Widget>[
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(22),
              gradient: const LinearGradient(
                colors: <Color>[Color(0xFF154B41), Color(0xFF2F8D72)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              boxShadow: const <BoxShadow>[
                BoxShadow(
                  blurRadius: 30,
                  color: Color(0x22154B41),
                  offset: Offset(0, 16),
                ),
              ],
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  controller.connectionLabel,
                  style: textTheme.titleLarge?.copyWith(
                    color: Colors.white,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  controller.running
                      ? 'Traffic is flowing through the local daemon.'
                      : 'Left-click the tray icon to start the daemon.',
                  style: textTheme.bodyMedium?.copyWith(
                    color: Colors.white.withValues(alpha: 0.86),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          _InfoCard(
            title: 'Runtime',
            rows: <_InfoRow>[
              _InfoRow('Mode', controller.modeDescription),
              _InfoRow('Hops', '${controller.selectedHops}'),
              _InfoRow('Known peers', '${controller.snapshot.knownPeers}'),
              _InfoRow(
                'Bandwidth',
                controller.formatBandwidth(
                  controller.snapshot.bandwidthUsedBytes,
                ),
              ),
              if (controller.snapshot.listenAddr.isNotEmpty)
                _InfoRow('Listen', controller.snapshot.listenAddr),
              if (controller.startedAtLabel != null)
                _InfoRow('Started', controller.startedAtLabel!),
            ],
          ),
          const SizedBox(height: 16),
          _InfoCard(
            title: 'Identity',
            rows: <_InfoRow>[
              _InfoRow(
                'Node ID',
                controller.nodeID.isEmpty ? 'Unavailable' : controller.nodeID,
                selectable: true,
              ),
            ],
          ),
          if (circuit != null) ...<Widget>[
            const SizedBox(height: 16),
            _InfoCard(
              title: 'Circuit',
              rows: <_InfoRow>[
                _InfoRow('Streams', '${circuit.streams}'),
                _InfoRow(
                  'Created',
                  circuit.createdAt.toLocal().toIso8601String().replaceFirst(
                    'T',
                    ' ',
                  ),
                ),
                _InfoRow('Path', circuit.path.join(' -> '), selectable: true),
              ],
            ),
          ],
          if (controller.notice case final notice?) ...<Widget>[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFFFFF3E6),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(color: const Color(0xFFE6B06E)),
              ),
              child: Text(
                notice,
                style: textTheme.bodyMedium?.copyWith(
                  color: const Color(0xFF8A5317),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({required this.title, required this.rows});

  final String title;
  final List<_InfoRow> rows;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFFE4E8E0)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            title,
            style: textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 12),
          for (var index = 0; index < rows.length; index++) ...<Widget>[
            _InfoRowView(row: rows[index]),
            if (index < rows.length - 1)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 12),
                child: Divider(height: 1),
              ),
          ],
        ],
      ),
    );
  }
}

class _InfoRow {
  const _InfoRow(this.label, this.value, {this.selectable = false});

  final String label;
  final String value;
  final bool selectable;
}

class _InfoRowView extends StatelessWidget {
  const _InfoRowView({required this.row});

  final _InfoRow row;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        SizedBox(
          width: 110,
          child: Text(
            row.label,
            style: textTheme.bodyMedium?.copyWith(
              color: const Color(0xFF61706B),
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
        Expanded(
          child: row.selectable
              ? SelectableText(
                  row.value,
                  style: textTheme.bodyMedium?.copyWith(
                    color: const Color(0xFF11211D),
                  ),
                )
              : Text(
                  row.value,
                  style: textTheme.bodyMedium?.copyWith(
                    color: const Color(0xFF11211D),
                  ),
                ),
        ),
      ],
    );
  }
}
