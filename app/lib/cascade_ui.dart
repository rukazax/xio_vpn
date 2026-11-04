/// Экран «Каскад» — платная двухсерверная схема XIO.
///
/// Устройство (IPv4) → bridge-сервер (IPv4) → exit-сервер (только IPv6).
///
/// ## Где включить маршрут
///
/// Экран уже объявлен как [CascadeScreen.routeName] и зарегистрирован
/// в `main.dart` (полная версия) и `client_main.dart` (клиентская версия):
///
/// ```dart
/// Navigator.of(context).pushNamed(CascadeScreen.routeName);
/// ```
///
/// либо напрямую:
///
/// ```dart
/// Navigator.of(context).push(
///   MaterialPageRoute<void>(builder: (_) => const CascadeScreen()),
/// );
/// ```
///
/// ## Что осталось (заглушки)
///
/// 1. **Реальная подписка** — `CascadeFeatureGate`: `enabled` всегда false,
///    `requestActivation()` всегда false. Нужны проверка чека/подписочного
///    сервера, состояние `CascadeSubscription.entitled` и снятие замка.
/// 2. **Реальные пинги** — сейчас `pingMs` подставляется демо-значением при
///    «Переподключить»; нужен замер до bridge и до exit (два независимых
///    значения) и обновление `updatedAt` по таймеру/потоку статусов.
/// 3. **Выбор серверов** — станции bridge/exit захардкожены в
///    `CascadeRoute.idle()` / `_demoRoute()`; нужен список стран, выбор
///    exit-сервера только с IPv6 и сохранение выбора в состоянии приложения.
/// 4. Подключить подписи станций к локализации (`l10n.dart`) и связать
///    стадию каскада с реальным состоянием туннеля из `core.dart`.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import 'cascade_model.dart';

/// Цвет линии/станции для стадии каскада.
Color cascadeStageColor(BuildContext context, CascadeStage stage) {
  final scheme = Theme.of(context).colorScheme;
  return switch (stage) {
    CascadeStage.idle => scheme.outline,
    CascadeStage.deviceToBridge => const Color(0xFFFFB300),
    CascadeStage.bridgeToExit => const Color(0xFF2ECC71),
    CascadeStage.active => const Color(0xFF2ECC71),
    CascadeStage.degraded => const Color(0xFFFFB300),
    CascadeStage.failed => const Color(0xFFE53935),
  };
}

/// Подпись под схемой для каждой стадии.
String cascadeStatusCaption(CascadeStage stage) => switch (stage) {
  CascadeStage.idle => 'Готов к подключению',
  CascadeStage.deviceToBridge => 'Устройство → Bridge · подключение',
  CascadeStage.bridgeToExit => 'Bridge → Exit · туннель активен',
  CascadeStage.active => 'Защищённый туннель только IPv6',
  CascadeStage.degraded => 'Связь потеряна · повтор через 5 с',
  CascadeStage.failed => 'Каскад не построен · проверьте exit-сервер',
};

/// Полноэкранный экран «Каскад».
///
/// Ровно один экран в размер телефона: [Scaffold] + [SafeArea] + [Column]
/// c [Expanded]-блоками. Прокрутки нет намеренно — всё сжимается через
/// [FittedBox]/[Flexible] и ограничение `maxLines`, поэтому крупные шрифты
/// (`MediaQuery.textScaler`) не вылезают за экран.
class CascadeScreen extends StatefulWidget {
  const CascadeScreen({
    super.key,
    this.initialRoute,
    this.subscription,
    this.featureGate,
  });

  /// Имя маршрута для `Navigator.pushNamed`.
  static const String routeName = '/cascade';

  /// Начальное состояние схемы (по умолчанию демо-маршрут с активным туннелем).
  final CascadeRoute? initialRoute;

  /// Подписка; по умолчанию заглушка без подписки.
  final CascadeSubscription? subscription;

  /// Ворота платной функции; по умолчанию [CascadeFeatureGate].
  final CascadeFeatureGate? featureGate;

  @override
  State<CascadeScreen> createState() => _CascadeScreenState();
}

class _CascadeScreenState extends State<CascadeScreen>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  static const CascadeSubscription _stubSubscription = CascadeSubscription();

  late CascadeRoute _route;
  late final AnimationController _dots;
  Timer? _stepTimer;
  bool _visible = true;

  CascadeSubscription get _subscription =>
      widget.subscription ?? _stubSubscription;

  CascadeFeatureGate get _gate => widget.featureGate ?? const CascadeFeatureGate();

  @override
  void initState() {
    super.initState();
    _route = widget.initialRoute ?? _demoRoute();
    _dots = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1600),
    );
    WidgetsBinding.instance.addObserver(this);
    _syncAnimation();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stepTimer?.cancel();
    _dots.dispose();
    super.dispose();
  }

  /// A backgrounded screen must not keep the "running dots" ticker scheduled:
  /// the animation is only decorative and stops while the app is not visible.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final visible = state == AppLifecycleState.resumed;
    if (visible == _visible) return;
    _visible = visible;
    if (!visible) {
      _stepTimer?.cancel();
      _stepTimer = null;
      _dots.stop();
    } else {
      _syncAnimation();
    }
  }

  /// Демо-маршрут: bridge в Нидерландах (IPv4), exit в Швеции (IPv6).
  static CascadeRoute _demoRoute() => CascadeRoute(
    device: const CascadeHop(
      countryCode: '',
      label: 'Устройство',
      address: '192.168.1.10 · IPv4',
      state: CascadeHopState.connected,
    ),
    bridge: const CascadeHop(
      countryCode: 'NL',
      label: 'Bridge',
      address: '185.14.30.7 · IPv4',
      state: CascadeHopState.connected,
    ),
    exit: const CascadeHop(
      countryCode: 'SE',
      label: 'Exit',
      address: '2001:db8::7 · IPv6',
      state: CascadeHopState.connected,
    ),
    stage: CascadeStage.active,
    pingMs: 38,
    updatedAt: DateTime.now(),
  );

  void _syncAnimation() {
    if (_visible && _route.isAnimating) {
      if (!_dots.isAnimating) _dots.repeat();
    } else if (_dots.isAnimating) {
      _dots.stop();
    }
  }

  /// «Переподключить»: устройство → bridge, затем bridge → exit, затем активно.
  void _reconnect() {
    _stepTimer?.cancel();
    setState(() {
      _route = _route.copyWith(
        stage: CascadeStage.deviceToBridge,
        clearPing: true,
        updatedAt: DateTime.now(),
        device: _route.device.copyWith(state: CascadeHopState.connecting),
        bridge: _route.bridge.copyWith(state: CascadeHopState.connecting),
        exit: _route.exit.copyWith(state: CascadeHopState.idle),
      );
    });
    _syncAnimation();
    _stepTimer = Timer(const Duration(milliseconds: 1800), () {
      if (!mounted) return;
      setState(() {
        _route = _route.copyWith(
          stage: CascadeStage.bridgeToExit,
          updatedAt: DateTime.now(),
          device: _route.device.copyWith(state: CascadeHopState.connected),
          bridge: _route.bridge.copyWith(state: CascadeHopState.connected),
          exit: _route.exit.copyWith(state: CascadeHopState.connecting),
        );
      });
      _syncAnimation();
      _stepTimer = Timer(const Duration(milliseconds: 1600), () {
        if (!mounted) return;
        setState(() {
          _route = _route.copyWith(
            stage: CascadeStage.active,
            pingMs: 38,
            updatedAt: DateTime.now(),
            exit: _route.exit.copyWith(state: CascadeHopState.connected),
          );
        });
        _syncAnimation();
      });
    });
  }

  Future<void> _activate() async {
    final granted = await _gate.requestActivation();
    if (!mounted) return;
    if (granted) {
      // Появится вместе с реальной подпиской.
      setState(() {});
      return;
    }
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        const SnackBar(
          content: Text(CascadeFeatureGate.notConnectedMessage),
          behavior: SnackBarBehavior.floating,
        ),
      );
  }

  @override
  Widget build(BuildContext context) {
    final subscription = _subscription;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Каскад'),
        centerTitle: false,
        actions: <Widget>[
          IconButton(
            tooltip: CascadeFeatureGate.bannerText,
            onPressed: _activate,
            icon: Icon(
              subscription.entitled ? Icons.lock_open : Icons.lock_outline,
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 10, 16, 12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Expanded(flex: 5, child: _buildScheme(context, subscription)),
              const SizedBox(height: 10),
              Expanded(flex: 4, child: _buildStatus(context)),
              const SizedBox(height: 10),
              Expanded(flex: 4, child: _buildSubscription(context, subscription)),
            ],
          ),
        ),
      ),
    );
  }

  // ---------------------------------------------------------------- схема ---

  Widget _buildScheme(BuildContext context, CascadeSubscription subscription) {
    final theme = Theme.of(context);
    final stage = _route.stage;
    return Card(
      margin: EdgeInsets.zero,
      clipBehavior: Clip.antiAlias,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(6, 8, 6, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Expanded(
              child: Stack(
                children: <Widget>[
                  Positioned.fill(
                    child: Center(
                      child: FittedBox(
                        fit: BoxFit.scaleDown,
                        child: RepaintBoundary(
                          child: SizedBox(
                            width: 300,
                            height: 96,
                            // The stations are passed as `child` so a running
                            // "dots" animation repaints only the painter instead
                            // of rebuilding the three station widgets at 60 fps.
                            child: AnimatedBuilder(
                              animation: _dots,
                              child: _buildStations(context),
                              builder: (context, child) => CustomPaint(
                                painter: _CascadeSchemePainter(
                                  stage: stage,
                                  t: _dots.value,
                                  surfaceColor: theme.colorScheme.surface,
                                ),
                                child: child,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                  if (!subscription.entitled)
                    Positioned.fill(
                      child: IgnorePointer(
                        child: Container(
                          decoration: BoxDecoration(
                            color: theme.colorScheme.surface.withValues(
                              alpha: 0.78,
                            ),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          padding: const EdgeInsets.all(8),
                          child: Center(
                            child: FittedBox(
                              fit: BoxFit.scaleDown,
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: <Widget>[
                                  Icon(
                                    Icons.lock_outline,
                                    size: 16,
                                    color: theme.colorScheme.onSurfaceVariant,
                                  ),
                                  const SizedBox(width: 6),
                                  Text(
                                    'Платная функция',
                                    maxLines: 1,
                                    style: theme.textTheme.labelLarge?.copyWith(
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(height: 6),
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.center,
                child: Text(
                  cascadeStatusCaption(stage),
                  maxLines: 1,
                  softWrap: false,
                  textAlign: TextAlign.center,
                  style: theme.textTheme.labelMedium?.copyWith(
                    color: stage == CascadeStage.failed
                        ? const Color(0xFFE53935)
                        : theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Три станции внутри фиксированного «полотна» 300×96.
  Widget _buildStations(BuildContext context) {
    return Stack(
      children: <Widget>[
        ..._station(context, 46, _route.device, 'Устройство', Icons.smartphone),
        ..._station(context, 150, _route.bridge, 'Bridge', Icons.dns),
        ..._station(context, 254, _route.exit, 'Exit', Icons.public),
      ],
    );
  }

  List<Widget> _station(
    BuildContext context,
    double centerX,
    CascadeHop hop,
    String title,
    IconData icon,
  ) {
    final theme = Theme.of(context);
    final color = _hopColor(context, hop.state);
    return <Widget>[
      Positioned(
        left: centerX - 24,
        top: 8,
        width: 48,
        height: 48,
        child: Container(
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: color.withValues(alpha: 0.16),
            border: Border.all(color: color, width: 2),
          ),
          alignment: Alignment.center,
          child: FittedBox(
            fit: BoxFit.scaleDown,
            child: Padding(
              padding: const EdgeInsets.all(4),
              child: hop.countryCode.isEmpty
                  ? Icon(icon, size: 22, color: color)
                  : Text(hop.flag, style: const TextStyle(fontSize: 22)),
            ),
          ),
        ),
      ),
      Positioned(
        left: centerX - 46,
        top: 60,
        width: 92,
        height: 32,
        child: Column(
          children: <Widget>[
            Expanded(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: Text(
                  title,
                  maxLines: 1,
                  softWrap: false,
                  style: theme.textTheme.labelMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
            Expanded(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: Text(
                  hop.countryCode.isEmpty
                      ? 'IPv4'
                      : '${hop.countryCode} · ${hop.address.split(' ').first}',
                  maxLines: 1,
                  softWrap: false,
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    ];
  }

  Color _hopColor(BuildContext context, CascadeHopState state) {
    final scheme = Theme.of(context).colorScheme;
    return switch (state) {
      CascadeHopState.idle => scheme.outline,
      CascadeHopState.connecting => const Color(0xFFFFB300),
      CascadeHopState.connected => const Color(0xFF2ECC71),
      CascadeHopState.degraded => const Color(0xFFFFB300),
      CascadeHopState.failed => const Color(0xFFE53935),
    };
  }

  // --------------------------------------------------------------- статус ---

  Widget _buildStatus(BuildContext context) {
    final ping = _route.pingMs == null ? '—' : '${_route.pingMs} мс';
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Flexible(
              child: _statusLine(
                context,
                Icons.speed,
                'Пинг',
                ping,
                valueColor: _route.pingMs == null
                    ? null
                    : _hopColor(context, CascadeHopState.connected),
              ),
            ),
            const SizedBox(height: 6),
            Flexible(
              child: _statusLine(
                context,
                Icons.update,
                'Обновлено',
                _formatTime(_route.updatedAt),
              ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: _reconnect,
                icon: const Icon(Icons.refresh, size: 18),
                label: const FittedBox(
                  fit: BoxFit.scaleDown,
                  child: Text('Переподключить', maxLines: 1, softWrap: false),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _statusLine(
    BuildContext context,
    IconData icon,
    String label,
    String value, {
    Color? valueColor,
  }) {
    final theme = Theme.of(context);
    return FittedBox(
      fit: BoxFit.scaleDown,
      alignment: Alignment.centerLeft,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Icon(icon, size: 18, color: theme.colorScheme.onSurfaceVariant),
          const SizedBox(width: 8),
          Text(
            label,
            maxLines: 1,
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(width: 12),
          Text(
            value,
            maxLines: 1,
            style: theme.textTheme.bodyMedium?.copyWith(
              fontWeight: FontWeight.w600,
              color: valueColor,
              fontFeatures: const <FontFeature>[FontFeature.tabularFigures()],
            ),
          ),
        ],
      ),
    );
  }

  // ------------------------------------------------------------ подписка ---

  Widget _buildSubscription(
    BuildContext context,
    CascadeSubscription subscription,
  ) {
    final theme = Theme.of(context);
    return Card(
      margin: EdgeInsets.zero,
      color: subscription.entitled
          ? theme.colorScheme.surfaceContainerHigh
          : theme.colorScheme.errorContainer.withValues(alpha: 0.35),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: <Widget>[
                    Icon(
                      subscription.entitled
                          ? Icons.verified_outlined
                          : Icons.workspace_premium_outlined,
                      size: 18,
                      color: subscription.entitled
                          ? _hopColor(context, CascadeHopState.connected)
                          : theme.colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      subscription.entitled
                          ? subscription.planLabel
                          : CascadeFeatureGate.bannerText,
                      maxLines: 1,
                      softWrap: false,
                      style: theme.textTheme.titleSmall,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 6),
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Text(
                  subscription.entitled
                      ? 'Каскад доступен: устройство → bridge → exit (IPv6)'
                      : 'Подписка откроет второй сервер и exit только по IPv6',
                  maxLines: 1,
                  softWrap: false,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: Row(
                children: <Widget>[
                  Expanded(
                    child: OutlinedButton(
                      onPressed: _activate,
                      child: const FittedBox(
                        fit: BoxFit.scaleDown,
                        child: Text(
                          'Активировать',
                          maxLines: 1,
                          softWrap: false,
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  static String _formatTime(DateTime? time) {
    if (time == null) return '—';
    final local = time.toLocal();
    String two(int value) => value.toString().padLeft(2, '0');
    return '${two(local.hour)}:${two(local.minute)}:${two(local.second)}';
  }
}

/// Линия между станциями с «бегущими точками».
class _CascadeSchemePainter extends CustomPainter {
  _CascadeSchemePainter({
    required this.stage,
    required this.t,
    required this.surfaceColor,
  });

  final CascadeStage stage;
  final double t;
  final Color surfaceColor;

  static const double _y = 32;
  static const double _firstFrom = 70;
  static const double _firstTo = 126;
  static const double _secondFrom = 174;
  static const double _secondTo = 230;

  static const Color _grey = Color(0xFF9E9E9E);
  static const Color _yellow = Color(0xFFFFB300);
  static const Color _green = Color(0xFF2ECC71);
  static const Color _red = Color(0xFFE53935);

  Color _color({required bool first}) => switch (stage) {
    CascadeStage.idle => _grey,
    CascadeStage.deviceToBridge => first ? _yellow : _grey,
    CascadeStage.bridgeToExit => first ? _green : _yellow,
    CascadeStage.active => _green,
    CascadeStage.degraded => _yellow,
    CascadeStage.failed => _red,
  };

  bool _animating({required bool first}) =>
      (first && stage == CascadeStage.deviceToBridge) ||
      (!first && stage == CascadeStage.bridgeToExit);

  @override
  void paint(Canvas canvas, Size size) {
    _segment(
      canvas,
      _firstFrom,
      _firstTo,
      _color(first: true),
      _animating(first: true),
    );
    _segment(
      canvas,
      _secondFrom,
      _secondTo,
      _color(first: false),
      _animating(first: false),
    );
  }

  void _segment(
    Canvas canvas,
    double from,
    double to,
    Color color,
    bool animating,
  ) {
    final line = Paint()
      ..color = color
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(Offset(from, _y), Offset(to, _y), line);
    if (!animating) return;
    final dot = Paint()..color = surfaceColor;
    const count = 3;
    final length = to - from;
    for (var i = 0; i < count; i++) {
      final offset = ((t + i / count) % 1.0) * length;
      canvas.drawCircle(Offset(from + offset, _y), 3.2, dot);
    }
  }

  @override
  bool shouldRepaint(covariant _CascadeSchemePainter oldDelegate) =>
      oldDelegate.t != t ||
      oldDelegate.stage != stage ||
      oldDelegate.surfaceColor != surfaceColor;
}
