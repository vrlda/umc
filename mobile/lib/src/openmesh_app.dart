import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'openmesh_controller.dart';
import 'openmesh_platform.dart';

class OpenMeshApp extends StatefulWidget {
  const OpenMeshApp({super.key, OpenMeshPlatform? platform})
      : platform = platform ?? const MethodChannelOpenMeshPlatform();

  final OpenMeshPlatform platform;

  @override
  State<OpenMeshApp> createState() => _OpenMeshAppState();
}

class _OpenMeshAppState extends State<OpenMeshApp> {
  late final OpenMeshController _controller;

  @override
  void initState() {
    super.initState();
    _controller = OpenMeshController(platform: widget.platform);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final textTheme = GoogleFonts.spaceGroteskTextTheme();
    return MaterialApp(
      title: 'OpenMesh',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.light,
        useMaterial3: true,
        textTheme: textTheme,
        colorScheme: const ColorScheme.light(
          primary: Color(0xFFB2542C),
          secondary: Color(0xFF2E6761),
          surface: Color(0xFFFFF8F0),
        ),
        scaffoldBackgroundColor: const Color(0xFFF5EFE5),
      ),
      home: OpenMeshScreen(controller: _controller),
    );
  }
}

class OpenMeshScreen extends StatefulWidget {
  const OpenMeshScreen({super.key, required this.controller});

  final OpenMeshController controller;

  @override
  State<OpenMeshScreen> createState() => _OpenMeshScreenState();
}

class _OpenMeshScreenState extends State<OpenMeshScreen> {
  @override
  void initState() {
    super.initState();
    widget.controller.initialize();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.controller,
      builder: (context, _) {
        final controller = widget.controller;
        return Scaffold(
          body: DecoratedBox(
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: <Color>[
                  Color(0xFFF8F1E7),
                  Color(0xFFE8D3B8),
                  Color(0xFFD7E4DF),
                ],
              ),
            ),
            child: SafeArea(
              child: Stack(
                children: <Widget>[
                  const _BackdropShapes(),
                  ListView(
                    padding: const EdgeInsets.fromLTRB(20, 20, 20, 28),
                    children: <Widget>[
                      Text(
                        'OpenMesh',
                        style:
                            Theme.of(context).textTheme.displaySmall?.copyWith(
                                  fontWeight: FontWeight.w700,
                                  letterSpacing: -1,
                                ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        controller.connected
                            ? 'Private tunnel is active.'
                            : 'Tap once to route traffic through OpenMesh.',
                        style: Theme.of(context)
                            .textTheme
                            .titleMedium
                            ?.copyWith(color: const Color(0xFF4A534C)),
                      ),
                      const SizedBox(height: 24),
                      _StatusCard(controller: controller),
                      const SizedBox(height: 18),
                      _ControlCard(
                        title: 'Route',
                        child: _ConnectionToggle(controller: controller),
                      ),
                      const SizedBox(height: 14),
                      _ControlCard(
                        title: 'Hop Count',
                        child: _HopSelector(controller: controller),
                      ),
                      const SizedBox(height: 14),
                      _ControlCard(
                        title: 'Contribute',
                        child: _ModeSelector(controller: controller),
                      ),
                      const SizedBox(height: 14),
                      _ControlCard(
                        title: 'Traffic',
                        child: _TrafficPanel(controller: controller),
                      ),
                      if (controller.bannerMessage != null) ...<Widget>[
                        const SizedBox(height: 14),
                        _BannerMessage(message: controller.bannerMessage!),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.controller});

  final OpenMeshController controller;

  @override
  Widget build(BuildContext context) {
    final activeColor = controller.connected
        ? const Color(0xFF2E6761)
        : const Color(0xFF7C776D);
    final statusText = controller.connected ? 'Connected' : 'Disconnected';
    final subtitle = controller.relaySuspended
        ? 'Relay paused to protect battery below 20%.'
        : controller.snapshot.nodeId.isEmpty
            ? 'Waiting for Android bridge…'
            : 'Node ${_shortNodeId(controller.snapshot.nodeId)}';

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Colors.white.withValues(alpha: 0.78),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: Colors.white.withValues(alpha: 0.7)),
        boxShadow: const <BoxShadow>[
          BoxShadow(
            color: Color(0x15000000),
            blurRadius: 24,
            offset: Offset(0, 14),
          ),
        ],
      ),
      child: Row(
        children: <Widget>[
          Container(
            width: 16,
            height: 16,
            decoration: BoxDecoration(
              color: activeColor,
              shape: BoxShape.circle,
              boxShadow: <BoxShadow>[
                BoxShadow(
                  color: activeColor.withValues(alpha: 0.35),
                  blurRadius: 12,
                  spreadRadius: 2,
                ),
              ],
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  statusText,
                  style: Theme.of(
                    context,
                  ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: const Color(0xFF5C615A),
                      ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _shortNodeId(String nodeId) {
    if (nodeId.length <= 12) {
      return nodeId;
    }
    return '${nodeId.substring(0, 6)}…${nodeId.substring(nodeId.length - 4)}';
  }
}

class _ControlCard extends StatelessWidget {
  const _ControlCard({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(18, 18, 18, 16),
      decoration: BoxDecoration(
        color: const Color(0xFFFDF9F2).withValues(alpha: 0.9),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0xFFD7CCBE)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            title,
            style: Theme.of(
              context,
            ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 14),
          child,
        ],
      ),
    );
  }
}

class _ConnectionToggle extends StatelessWidget {
  const _ConnectionToggle({required this.controller});

  final OpenMeshController controller;

  @override
  Widget build(BuildContext context) {
    final connected = controller.connected;
    final busy = controller.busy;

    return Center(
      child: GestureDetector(
        onTap: busy ? null : controller.toggleConnection,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 220),
          curve: Curves.easeOutCubic,
          width: 236,
          height: 94,
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(999),
            gradient: LinearGradient(
              colors: connected
                  ? const <Color>[Color(0xFF2E6761), Color(0xFF4E8C85)]
                  : const <Color>[Color(0xFFB2542C), Color(0xFFD8895B)],
            ),
            boxShadow: <BoxShadow>[
              BoxShadow(
                color: (connected
                        ? const Color(0xFF2E6761)
                        : const Color(0xFFB2542C))
                    .withValues(alpha: 0.32),
                blurRadius: 24,
                offset: const Offset(0, 14),
              ),
            ],
          ),
          child: Row(
            children: <Widget>[
              AnimatedAlign(
                duration: const Duration(milliseconds: 220),
                alignment:
                    connected ? Alignment.centerRight : Alignment.centerLeft,
                child: Container(
                  width: 74,
                  height: 74,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.white,
                    boxShadow: const <BoxShadow>[
                      BoxShadow(
                        color: Color(0x22000000),
                        blurRadius: 10,
                        offset: Offset(0, 6),
                      ),
                    ],
                  ),
                  child: busy
                      ? const Padding(
                          padding: EdgeInsets.all(22),
                          child: CircularProgressIndicator(strokeWidth: 3),
                        )
                      : Icon(
                          connected
                              ? Icons.shield_moon
                              : Icons.power_settings_new,
                          color: connected
                              ? const Color(0xFF2E6761)
                              : const Color(0xFFB2542C),
                          size: 32,
                        ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Text(
                  connected ? 'Disconnect' : 'Connect',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.w700,
                      ),
                ),
              ),
              const SizedBox(width: 12),
            ],
          ),
        ),
      ),
    );
  }
}

class _HopSelector extends StatelessWidget {
  const _HopSelector({required this.controller});

  final OpenMeshController controller;

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: List<Widget>.generate(3, (int index) {
        final hops = index + 1;
        final selected = controller.selectedHops == hops;
        return ChoiceChip(
          label: Text('$hops hop${hops == 1 ? '' : 's'}'),
          selected: selected,
          onSelected: (_) => controller.selectHops(hops),
          selectedColor: const Color(0xFF2E6761),
          backgroundColor: const Color(0xFFF3E8D9),
          labelStyle: TextStyle(
            color: selected ? Colors.white : const Color(0xFF4D4A45),
            fontWeight: FontWeight.w600,
          ),
          side: BorderSide(
            color: selected ? const Color(0xFF2E6761) : const Color(0xFFD1BFA8),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        );
      }),
    );
  }
}

class _ModeSelector extends StatelessWidget {
  const _ModeSelector({required this.controller});

  final OpenMeshController controller;

  @override
  Widget build(BuildContext context) {
    return SegmentedButton<OpenMeshContributionMode>(
      showSelectedIcon: false,
      style: ButtonStyle(
        backgroundColor: WidgetStateProperty.resolveWith<Color?>((states) {
          if (states.contains(WidgetState.selected)) {
            return const Color(0xFFB2542C);
          }
          return const Color(0xFFF3E8D9);
        }),
        foregroundColor: WidgetStateProperty.resolveWith<Color?>((states) {
          if (states.contains(WidgetState.selected)) {
            return Colors.white;
          }
          return const Color(0xFF4D4A45);
        }),
        textStyle: WidgetStateProperty.all(
          const TextStyle(fontWeight: FontWeight.w700),
        ),
        side: WidgetStateProperty.resolveWith<BorderSide?>((states) {
          if (states.contains(WidgetState.selected)) {
            return const BorderSide(color: Color(0xFFB2542C));
          }
          return const BorderSide(color: Color(0xFFD1BFA8));
        }),
      ),
      segments: OpenMeshContributionMode.values
          .map(
            (mode) => ButtonSegment<OpenMeshContributionMode>(
              value: mode,
              label: Text(mode.label),
            ),
          )
          .toList(growable: false),
      selected: <OpenMeshContributionMode>{controller.selectedMode},
      onSelectionChanged: (selection) {
        if (selection.isNotEmpty) {
          controller.selectMode(selection.first);
        }
      },
    );
  }
}

class _TrafficPanel extends StatelessWidget {
  const _TrafficPanel({required this.controller});

  final OpenMeshController controller;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: <Widget>[
        Expanded(
          child: _TrafficPill(
            accent: const Color(0xFF2E6761),
            icon: Icons.south,
            label: 'Down',
            value: _formatBytes(controller.snapshot.bytesIn),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: _TrafficPill(
            accent: const Color(0xFFB2542C),
            icon: Icons.north,
            label: 'Up',
            value: _formatBytes(controller.snapshot.bytesOut),
          ),
        ),
      ],
    );
  }

  String _formatBytes(int bytes) {
    const units = <String>['B', 'KB', 'MB', 'GB', 'TB'];
    double value = bytes.toDouble();
    int unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex++;
    }

    final precision = value >= 10 || unitIndex == 0 ? 0 : 1;
    return '${value.toStringAsFixed(precision)} ${units[unitIndex]}';
  }
}

class _TrafficPill extends StatelessWidget {
  const _TrafficPill({
    required this.accent,
    required this.icon,
    required this.label,
    required this.value,
  });

  final Color accent;
  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: accent.withValues(alpha: 0.2)),
      ),
      child: Row(
        children: <Widget>[
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: accent.withValues(alpha: 0.12),
              shape: BoxShape.circle,
            ),
            child: Icon(icon, color: accent),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(
                  label,
                  style: Theme.of(context).textTheme.labelLarge?.copyWith(
                        color: const Color(0xFF6A655D),
                      ),
                ),
                const SizedBox(height: 2),
                Text(
                  value,
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _BannerMessage extends StatelessWidget {
  const _BannerMessage({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: const Color(0xFF3F403F),
        borderRadius: BorderRadius.circular(18),
      ),
      child: Row(
        children: <Widget>[
          const Icon(Icons.info_outline, color: Colors.white),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: Colors.white),
            ),
          ),
        ],
      ),
    );
  }
}

class _BackdropShapes extends StatelessWidget {
  const _BackdropShapes();

  @override
  Widget build(BuildContext context) {
    return IgnorePointer(
      child: Stack(
        children: <Widget>[
          Positioned(
            top: -70,
            right: -40,
            child: _GlowOrb(size: 220, color: const Color(0x33B2542C)),
          ),
          Positioned(
            left: -30,
            bottom: 140,
            child: _GlowOrb(size: 180, color: const Color(0x332E6761)),
          ),
        ],
      ),
    );
  }
}

class _GlowOrb extends StatelessWidget {
  const _GlowOrb({required this.size, required this.color});

  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        gradient: RadialGradient(
          colors: <Color>[color, color.withValues(alpha: 0)],
        ),
      ),
    );
  }
}
