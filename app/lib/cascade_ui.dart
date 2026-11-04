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
/// ## Что делает экран
///
/// Кнопка «Проверить каскад» действительно опрашивает bridge по SSH и
/// показывает результат healthcheck-а: живой туннель, время ответа, реальный
/// выходной IPv6 и причину отказа. Никаких демо-таймеров и подставного пинга:
/// стадии схемы выставляются только по ответу сервера.
///
/// ## Что осталось (заглушки)
///
/// 1. **Реальная подписка** — `CascadeFeatureGate`: `enabled` всегда false,
///    `requestActivation()` всегда false. Нужны проверка чека/подписочного
///    сервера, состояние `CascadeSubscription.entitled` и снятие замка.
/// 2. **Выбор серверов** — станции bridge/exit захардкожены в
///    `CascadeRoute.idle()` / `cascadeRouteFromAddresses()`; нужен список
///    стран, выбор exit-сервера только с IPv6 и сохранение выбора в
///    состоянии приложения.
/// 3. Подключить подписи станций к локализации (`l10n.dart`) и связать
///    стадию каскада с реальным состоянием туннеля из `core.dart`.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'cascade_health.dart';
import 'cascade_model.dart';

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
    this.bridgeAddress = '',
    this.exitAddress = '',
    this.onSaveServers,
    this.unlocked = false,
    this.onUnlock,
    this.healthProbe,
  });

  /// Имя маршрута для `Navigator.pushNamed`.
  static const String routeName = '/cascade';

  /// Начальное состояние схемы (по умолчанию — маршрут из адресов настроек).
  final CascadeRoute? initialRoute;

  /// Подписка; по умолчанию заглушка без подписки.
  final CascadeSubscription? subscription;

  /// Ворота платной функции; по умолчанию [CascadeFeatureGate].
  final CascadeFeatureGate? featureGate;

  /// Свой bridge (IPv4 или домен). Пустая строка — каскад не настроен.
  final String bridgeAddress;

  /// Свой exit (только IPv6). Пустая строка — каскад не настроен.
  final String exitAddress;

  /// Сохранение адресов, введённых владельцем. Возвращает `false`, если
  /// ввод отклонён (тогда диалог показывает ошибку).
  final Future<bool> Function(String bridge, String exit)? onSaveServers;

  /// Разблокирован ли каскад. Биллинга пока нет: «Активировать» включает
  /// функцию бесплатно и сохраняет это в профиле приложения.
  final bool unlocked;

  /// Включение каскада по кнопке «Активировать».
  final Future<void> Function()? onUnlock;

  /// Реальная проверка каскада по SSH. `null` — в этой сборке проверка
  /// недоступна, и экран честно сообщит об этом вместо анимации.
  final CascadeHealthProbe? healthProbe;

  @override
  State<CascadeScreen> createState() => _CascadeScreenState();
}

class _CascadeScreenState extends State<CascadeScreen>
    with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  static const CascadeSubscription _stubSubscription = CascadeSubscription();

  /// Сколько ждём ответ проверки, прежде чем показать ошибку.
  static const Duration _healthDeadline = Duration(seconds: 15);

  late CascadeRoute _route;
  late bool _unlocked;
  late String _bridgeAddress;
  late String _exitAddress;
  late final AnimationController _dots;

  /// Идёт реальный SSH-опрос: кнопка заблокирована, точки бегут.
  bool _busy = false;

  /// Последний реальный результат проверки; `null` — ещё не проверяли.
  CascadeHealth? _health;
  Timer? _deadline;
  bool _visible = true;

  CascadeSubscription get _subscription {
    final base = widget.subscription ?? _stubSubscription;
    if (_unlocked && !base.entitled) {
      return const CascadeSubscription(
        entitled: true,
        planLabel: 'Включено · оплата пока не требуется',
      );
    }
    return base;
  }

  /// Каскад настроен, только если заданы оба адреса.
  bool get _configured =>
      validateCascadeBridge(_bridgeAddress) != null &&
      validateCascadeExit(_exitAddress) != null;

  @override
  void initState() {
    super.initState();
    _unlocked = widget.unlocked;
    _bridgeAddress = widget.bridgeAddress;
    _exitAddress = widget.exitAddress;
    _route =
        widget.initialRoute ??
        (_configured
            ? cascadeRouteFromAddresses(
                bridge: _bridgeAddress,
                exit: _exitAddress,
                updatedAt: DateTime.now(),
              )
            : cascadeRouteFromAddresses(bridge: '', exit: ''));
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
    _deadline?.cancel();
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
      _dots.stop();
    } else {
      _syncAnimation();
    }
  }

  void _syncAnimation() {
    final running = _visible && _busy;
    if (running) {
      if (!_dots.isAnimating) _dots.repeat();
    } else if (_dots.isAnimating) {
      _dots.stop();
    }
  }

  /// Подпись под схемой: только факты, без демонстрационных стадий.
  String get _caption {
    if (_busy) return 'Проверка bridge и exit по SSH…';
    if (!_configured) return 'Каскад не настроен · укажите серверы';
    return _health?.caption() ?? cascadeStatusCaption(_route.stage);
  }

  /// «Проверить каскад»: реальный опрос сервера и честный статус.
  Future<void> _checkCascade() async {
    if (_busy) return;
    if (!_configured) {
      setState(() {
        _health = null;
        _route = cascadeRouteFromAddresses(bridge: '', exit: '');
      });
      _syncAnimation();
      return;
    }
    final probe = widget.healthProbe;
    if (probe == null) {
      setState(() {
        _health = CascadeHealth.failure(
          'Проверка недоступна: в этой сборке нет SSH-доступа к серверу',
        );
        _route = _routeFromHealth(_health!);
      });
      _syncAnimation();
      return;
    }
    setState(() {
      _busy = true;
      _route = _route.copyWith(
        stage: CascadeStage.deviceToBridge,
        clearPing: true,
        updatedAt: DateTime.now(),
        device: _route.device.copyWith(state: CascadeHopState.connected),
        bridge: _route.bridge.copyWith(state: CascadeHopState.connecting),
        exit: _route.exit.copyWith(state: CascadeHopState.idle),
      );
    });
    _syncAnimation();
    _deadline?.cancel();
    _deadline = Timer(_healthDeadline, () {
      if (!mounted || !_busy) return;
      _finish(
        CascadeHealth.failure(
          'Проверка не уложилась в ${_healthDeadline.inSeconds} с',
        ),
      );
    });
    CascadeHealth health;
    try {
      health = await probe(_bridgeAddress);
    } catch (_) {
      // Экран не показывает текст исключения: в нём бывают адреса и ключи.
      health = CascadeHealth.failure('Не удалось проверить каскад по SSH');
    } finally {
      _deadline?.cancel();
      _deadline = null;
    }
    if (!mounted || !_busy) return;
    _finish(health);
  }

  void _finish(CascadeHealth health) {
    _deadline?.cancel();
    _deadline = null;
    if (!mounted) return;
    setState(() {
      _busy = false;
      _health = health;
      _route = _routeFromHealth(health);
    });
    _syncAnimation();
  }

  /// Переносит вердикт healthcheck-а в схему и блок статуса.
  CascadeRoute _routeFromHealth(CascadeHealth health) {
    return _route.copyWith(
      stage: health.stage,
      pingMs: health.latencyMs,
      clearPing: health.latencyMs == null,
      updatedAt: health.checkedAt,
      device: _route.device.copyWith(
        address: 'IPv4',
        state: health.verdict == CascadeHealthVerdict.unconfigured
            ? CascadeHopState.idle
            : CascadeHopState.connected,
      ),
      bridge: _route.bridge.copyWith(
        address: _configured ? _bridgeAddress : 'не настроен',
        state: health.bridgeState,
      ),
      exit: _route.exit.copyWith(
        address: _configured ? _exitAddress : 'не настроен',
        state: health.exitState,
      ),
    );
  }

  Future<void> _activate() async {
    if (_unlocked) {
      ScaffoldMessenger.of(context)
        ..hideCurrentSnackBar()
        ..showSnackBar(
          const SnackBar(
            content: Text('Каскад уже включён'),
            behavior: SnackBarBehavior.floating,
          ),
        );
      return;
    }
    // Биллинга пока нет: кнопка включает функцию бесплатно.
    await widget.onUnlock?.call();
    if (!mounted) return;
    setState(() => _unlocked = true);
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        const SnackBar(
          content: Text('Каскад включён — оплата пока не требуется'),
          behavior: SnackBarBehavior.floating,
        ),
      );
  }

  /// Диалог «Серверы каскада»: свой bridge (IPv4/домен) и exit (только IPv6).
  Future<void> _editServers() async {
    final bridge = TextEditingController(text: _bridgeAddress);
    final exit = TextEditingController(text: _exitAddress);
    String? bridgeError;
    String? exitError;
    final saved = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setLocal) => AlertDialog(
          title: const Text('Серверы каскада'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                TextField(
                  controller: bridge,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: InputDecoration(
                    labelText: 'Bridge (IPv4 или домен)',
                    hintText: '81.177.142.37',
                    errorText: bridgeError,
                  ),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: exit,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: InputDecoration(
                    labelText: 'Exit (только IPv6)',
                    hintText: '2a0c:b641:1a0:800::2a2',
                    errorText: exitError,
                  ),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Устройство → bridge → exit. Туннель bridge → exit идёт только '
                  'по IPv6, поэтому bridge должен иметь IPv6-аплинк.',
                  style: TextStyle(fontSize: 12),
                ),
                const SizedBox(height: 12),
                ValueListenableBuilder<TextEditingValue>(
                  valueListenable: exit,
                  builder: (context, value, _) =>
                      _installCommandBlock(value.text.trim()),
                ),
              ],
            ),
          ),
          actions: <Widget>[
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: const Text('Отмена'),
            ),
            FilledButton(
              onPressed: () async {
                final bridgeText = bridge.text.trim();
                final exitText = exit.text.trim();
                setLocal(() {
                  bridgeError = bridgeText.isEmpty
                      ? null
                      : (validateCascadeBridge(bridgeText) == null
                            ? 'Нужен IPv4 или домен без схемы и порта'
                            : null);
                  exitError = exitText.isEmpty
                      ? null
                      : (validateCascadeExit(exitText) == null
                            ? 'Нужен IPv6-адрес'
                            : null);
                });
                if (bridgeError != null || exitError != null) return;
                final ok =
                    await widget.onSaveServers?.call(bridgeText, exitText) ??
                    false;
                if (!ok) {
                  setLocal(() => bridgeError = 'Не удалось сохранить адреса');
                  return;
                }
                if (dialogContext.mounted) {
                  Navigator.of(dialogContext).pop(true);
                }
              },
              child: const Text('Сохранить'),
            ),
          ],
        ),
      ),
    );
    if (saved == true) {
      setState(() {
        _bridgeAddress = bridge.text.trim();
        _exitAddress = exit.text.trim();
        // Новые адреса — новый предмет проверки: старый вердикт больше не
        // относится к этой паре серверов.
        _health = null;
        _route = cascadeRouteFromAddresses(
          bridge: _bridgeAddress,
          exit: _exitAddress,
          updatedAt: DateTime.now(),
        );
      });
      _syncAnimation();
    }
  }

  /// Команда установки каскада на bridge с уже подставленным адресом exit.
  Widget _installCommandBlock(String exit) {
    final address = exit.isEmpty ? '<ipv6-exit>' : exit;
    final command =
        'curl -fsSL https://raw.githubusercontent.com/rukazax/xio_vpn/main/'
        'deploy/cascade/terminal-install.sh | bash -s -- '
        '--role bridge --exit-host $address';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        const Text(
          'Установка на bridge (нужны docker/podman и IPv6):',
          style: TextStyle(fontSize: 12),
        ),
        const SizedBox(height: 6),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            command,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          ),
        ),
        Align(
          alignment: Alignment.centerRight,
          child: TextButton.icon(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: command));
              if (mounted) {
                ScaffoldMessenger.of(context)
                  ..hideCurrentSnackBar()
                  ..showSnackBar(
                    const SnackBar(
                      content: Text('Команда скопирована'),
                      behavior: SnackBarBehavior.floating,
                    ),
                  );
              }
            },
            icon: const Icon(Icons.copy, size: 16),
            label: const Text('Скопировать команду'),
          ),
        ),
      ],
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
            tooltip: 'Серверы каскада',
            onPressed: _editServers,
            icon: const Icon(Icons.dns_outlined),
          ),
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
              Expanded(
                flex: 4,
                child: _buildSubscription(context, subscription),
              ),
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
    final failed =
        stage == CascadeStage.failed ||
        _health?.verdict == CascadeHealthVerdict.failed;
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
                                  running: _busy,
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
                  _caption,
                  maxLines: 1,
                  softWrap: false,
                  textAlign: TextAlign.center,
                  style: theme.textTheme.labelMedium?.copyWith(
                    color: failed
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
                      ? (hop.address.isEmpty ? 'IPv4' : hop.address)
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
    final health = _health;
    final latency = _route.pingMs;
    final reason = health?.reason;
    final egress = health?.egressIpv6;
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
                'Отклик',
                latency == null ? '—' : '$latency мс',
                valueColor: latency == null
                    ? null
                    : _hopColor(context, CascadeHopState.connected),
              ),
            ),
            const SizedBox(height: 6),
            Flexible(
              child: _statusLine(
                context,
                Icons.public,
                'Выходной IPv6',
                egress ?? '—',
                valueColor: egress == null
                    ? null
                    : _hopColor(context, CascadeHopState.connected),
              ),
            ),
            const SizedBox(height: 6),
            Flexible(
              child: reason != null
                  ? _statusLine(
                      context,
                      Icons.error_outline,
                      'Причина',
                      _shortReason(reason),
                      valueColor: const Color(0xFFE53935),
                    )
                  : _statusLine(
                      context,
                      Icons.update,
                      'Обновлено',
                      _formatTime(_route.updatedAt),
                    ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: _busy ? null : _checkCascade,
                icon: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.fact_check_outlined, size: 18),
                label: FittedBox(
                  fit: BoxFit.scaleDown,
                  child: Text(
                    _busy ? 'Проверка…' : 'Проверить каскад',
                    maxLines: 1,
                    softWrap: false,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Причина в одну строку: подробности остаются в JSON healthcheck-а.
  static String _shortReason(String reason, [int max = 64]) {
    final text = reason.trim();
    if (text.length <= max) return text;
    return '${text.substring(0, max - 1)}…';
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
                    child: subscription.entitled
                        ? const Row(
                            children: <Widget>[
                              Icon(Icons.verified, size: 18),
                              SizedBox(width: 6),
                              Flexible(
                                child: Text(
                                  'Включено',
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          )
                        : OutlinedButton(
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
    this.running = false,
  });

  final CascadeStage stage;
  final double t;
  final Color surfaceColor;

  /// Точки бегут только пока действительно идёт SSH-опрос: никакой анимации
  /// «для красоты» на статичном результате.
  final bool running;

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

  bool _animating({required bool first}) => running && first;

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
      oldDelegate.running != running ||
      oldDelegate.surfaceColor != surfaceColor;
}
