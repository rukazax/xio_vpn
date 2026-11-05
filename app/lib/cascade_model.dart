/// Модель экрана «Каскад» — двухсерверная схема XIO.
///
/// Устройство (IPv4) → bridge-сервер (IPv4) → exit-сервер (только IPv6).
/// Файл намеренно не импортирует Flutter: модель используется и в UI
/// (`cascade_ui.dart`), и в тестах, и в персистентном состоянии через JSON.
library;

import 'dart:io';

/// Стадия построения / жизни каскада.
enum CascadeStage {
  /// Ничего не запущено.
  idle,

  /// Устройство устанавливает туннель до bridge-сервера.
  deviceToBridge,

  /// Bridge поднимает выходной туннель до exit-сервера (IPv6).
  bridgeToExit,

  /// Туннель активен, трафик идёт через оба сервера.
  active,

  /// Связь потеряна, идёт повтор.
  degraded,

  /// Построить каскад не удалось.
  failed,
}

/// Состояние одной станции каскада.
enum CascadeHopState { idle, connecting, connected, degraded, failed }

/// Станция маршрута: устройство, bridge или exit.
///
/// [countryCode] — двухбуквенный ISO-код страны (для эмодзи-флага),
/// [label] — короткая подпись («Устройство», «Bridge», «Exit»),
/// [address] — адрес станции (IPv4 для устройства/bridge, IPv6 для exit).
class CascadeHop {
  const CascadeHop({
    required this.countryCode,
    required this.label,
    required this.address,
    this.state = CascadeHopState.idle,
  });

  final String countryCode;
  final String label;
  final String address;
  final CascadeHopState state;

  /// Флаг страны, собранный из ISO-кода (🇷🇺 для `RU`).
  String get flag => flagEmoji(countryCode);

  CascadeHop copyWith({
    String? countryCode,
    String? label,
    String? address,
    CascadeHopState? state,
  }) => CascadeHop(
    countryCode: countryCode ?? this.countryCode,
    label: label ?? this.label,
    address: address ?? this.address,
    state: state ?? this.state,
  );

  Map<String, Object?> toJson() => <String, Object?>{
    'countryCode': countryCode,
    'label': label,
    'address': address,
    'state': state.name,
  };

  /// Терпимый к мусору разбор: отсутствующие поля заменяются заглушками,
  /// чтобы испорченное состояние не роняло экран.
  factory CascadeHop.fromJson(
    Object? json, {
    String fallbackLabel = '',
    String fallbackAddress = '',
  }) {
    if (json is! Map) {
      return CascadeHop(
        countryCode: '',
        label: fallbackLabel,
        address: fallbackAddress,
      );
    }
    return CascadeHop(
      countryCode: '${json['countryCode'] ?? ''}',
      label: '${json['label'] ?? fallbackLabel}',
      address: '${json['address'] ?? fallbackAddress}',
      state: cascadeHopStateFromName(json['state'] as String?),
    );
  }

  @override
  String toString() =>
      'CascadeHop($label, $countryCode, $address, ${state.name})';
}

/// Полный снимок каскадного маршрута.
class CascadeRoute {
  const CascadeRoute({
    required this.device,
    required this.bridge,
    required this.exit,
    this.stage = CascadeStage.idle,
    this.pingMs,
    this.updatedAt,
  });

  final CascadeHop device;
  final CascadeHop bridge;
  final CascadeHop exit;
  final CascadeStage stage;
  final int? pingMs;
  final DateTime? updatedAt;

  /// Пустая схема: показывается до первого подключения и в тестах.
  factory CascadeRoute.idle() => const CascadeRoute(
    device: CascadeHop(
      countryCode: '',
      label: 'Устройство',
      address: '192.168.1.10 · IPv4',
    ),
    bridge: CascadeHop(
      countryCode: 'NL',
      label: 'Bridge',
      address: '185.14.30.7 · IPv4',
    ),
    exit: CascadeHop(
      countryCode: 'SE',
      label: 'Exit',
      address: '2001:db8::7 · IPv6',
    ),
  );

  /// Идёт ли прямо сейчас анимация «бегущих точек».
  bool get isAnimating =>
      stage == CascadeStage.deviceToBridge ||
      stage == CascadeStage.bridgeToExit;

  /// Туннель поднят.
  bool get isTunnelActive => stage == CascadeStage.active;

  /// Связь есть, но нестабильна (повтор).
  bool get isDegraded => stage == CascadeStage.degraded;

  CascadeRoute copyWith({
    CascadeHop? device,
    CascadeHop? bridge,
    CascadeHop? exit,
    CascadeStage? stage,
    int? pingMs,
    DateTime? updatedAt,
    bool clearPing = false,
    bool clearUpdatedAt = false,
  }) => CascadeRoute(
    device: device ?? this.device,
    bridge: bridge ?? this.bridge,
    exit: exit ?? this.exit,
    stage: stage ?? this.stage,
    pingMs: clearPing ? null : (pingMs ?? this.pingMs),
    updatedAt: clearUpdatedAt ? null : (updatedAt ?? this.updatedAt),
  );

  Map<String, Object?> toJson() => <String, Object?>{
    'device': device.toJson(),
    'bridge': bridge.toJson(),
    'exit': exit.toJson(),
    'stage': stage.name,
    'pingMs': pingMs,
    'updatedAt': updatedAt?.toIso8601String(),
  };

  factory CascadeRoute.fromJson(Object? json) {
    if (json is! Map) return CascadeRoute.idle();
    final idle = CascadeRoute.idle();
    return CascadeRoute(
      device: CascadeHop.fromJson(
        json['device'],
        fallbackLabel: idle.device.label,
        fallbackAddress: idle.device.address,
      ),
      bridge: CascadeHop.fromJson(
        json['bridge'],
        fallbackLabel: idle.bridge.label,
        fallbackAddress: idle.bridge.address,
      ),
      exit: CascadeHop.fromJson(
        json['exit'],
        fallbackLabel: idle.exit.label,
        fallbackAddress: idle.exit.address,
      ),
      stage: cascadeStageFromName(json['stage'] as String?),
      pingMs: json['pingMs'] is num ? (json['pingMs'] as num).toInt() : null,
      updatedAt: json['updatedAt'] == null
          ? null
          : DateTime.tryParse('${json['updatedAt']}'),
    );
  }

  @override
  String toString() => 'CascadeRoute(${stage.name}, ${pingMs}ms)';
}

/// Подписка на платную функцию «Каскад».
///
/// Заглушка: реальная подписка ещё не подключена, поэтому по умолчанию
/// [entitled] = false и [planLabel] = «Подписка не подключена».
class CascadeSubscription {
  const CascadeSubscription({
    this.entitled = false,
    this.planLabel = 'Подписка не подключена',
  });

  final bool entitled;
  final String planLabel;

  CascadeSubscription copyWith({bool? entitled, String? planLabel}) =>
      CascadeSubscription(
        entitled: entitled ?? this.entitled,
        planLabel: planLabel ?? this.planLabel,
      );

  @override
  String toString() => 'CascadeSubscription($entitled, $planLabel)';
}

/// Ворота платной функции «Каскад».
///
/// Сейчас выключены намеренно: [enabled] всегда false, а
/// [requestActivation] всегда отвечает false. Это место под будущую
/// проверку подписки (магазин / подписочный сервер) — менять только здесь,
/// экран `CascadeScreen` уже готов принимать результат.
class CascadeFeatureGate {
  const CascadeFeatureGate();

  /// Единственный экземпляр для удобства вызова из UI.
  static const CascadeFeatureGate instance = CascadeFeatureGate();

  /// Баннер в блоке подписки.
  static const String bannerText = 'Платная функция. Требуется подписка';

  /// Текст SnackBar после неудачной активации.
  static const String notConnectedMessage = 'Подписка ещё не подключена';

  /// Включена ли функция. Пока всегда false — заглушка подписки.
  static bool get enabled => false;

  /// Попытка активировать подписку. Заглушка: всегда false.
  Future<bool> requestActivation() async {
    // TODO(подписка): здесь будет запрос к магазину/подписочному серверу.
    return false;
  }
}

/// Эмодзи-флаг из двухбуквенного ISO-кода (`RU` → 🇷🇺).
///
/// Без пакетов и сети: региональные индикаторы лежат подряд начиная
/// с U+1F1E6. Для неизвестного/пустого кода возвращается белый флаг.
String flagEmoji(String countryCode) {
  const unknown = '🏳';
  final code = countryCode.trim().toUpperCase();
  if (code.length != 2) return unknown;
  final units = <int>[];
  for (final unit in code.codeUnits) {
    if (unit < 0x41 || unit > 0x5A) return unknown;
    units.add(0x1F1E6 + (unit - 0x41));
  }
  return String.fromCharCodes(units);
}

/// Разбор [CascadeStage] из строки; неизвестное значение — [CascadeStage.idle].
CascadeStage cascadeStageFromName(String? name) {
  for (final stage in CascadeStage.values) {
    if (stage.name == name) return stage;
  }
  return CascadeStage.idle;
}

/// Разбор [CascadeHopState] из строки; неизвестное — [CascadeHopState.idle].
CascadeHopState cascadeHopStateFromName(String? name) {
  for (final state in CascadeHopState.values) {
    if (state.name == name) return state;
  }
  return CascadeHopState.idle;
}

/// Проверка адреса bridge: IPv4 или доменное имя (без схемы и порта).
///
/// Возвращает нормализованную строку или `null`, если ввод неверен. Пустая
/// строка — допустимое значение «не настроено» и тоже даёт `null`.
String? validateCascadeBridge(String value) {
  final text = value.trim();
  if (text.isEmpty || text.startsWith('[') || text.contains(':')) return null;
  final address = _cascadeIpv4(text);
  if (address != null) return address;
  final parts = text.split('.');
  // An invalid/legacy IPv4 spelling must not slip through as a DNS hostname.
  // A numeric final label is not a public DNS TLD.
  if (RegExp(r'^[0-9]+$').hasMatch(parts.last)) return null;
  final label = RegExp(r'^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$');
  if (text.length <= 253 &&
      parts.length >= 2 &&
      parts.every((p) => p.length <= 63 && label.hasMatch(p))) {
    return text.toLowerCase();
  }
  return null;
}

String? _cascadeIpv4(String text) {
  final octets = text.split('.');
  if (octets.length != 4 ||
      octets.any((p) => !RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(p))) {
    return null;
  }
  final address = InternetAddress.tryParse(text);
  if (address == null || address.type != InternetAddressType.IPv4) return null;
  return address.address;
}

/// Exit is a literal IPv4 or IPv6 address, never DNS, URL, scope or host:port.
/// Brackets are accepted only around IPv6. Parsing never performs DNS/network IO.
String? validateCascadeExit(String value) {
  final text = value.trim();
  if (text.isEmpty) return null;
  final bracketed = text.startsWith('[') && text.endsWith(']');
  final host = bracketed ? text.substring(1, text.length - 1) : text;
  if (!host.contains(':')) return bracketed ? null : _cascadeIpv4(host);
  if (!RegExp(r'^[0-9A-Fa-f:.]+$').hasMatch(host)) return null;
  final address = InternetAddress.tryParse(host);
  if (address == null || address.type != InternetAddressType.IPv6) return null;
  return InternetAddress.fromRawAddress(address.rawAddress).address
      .toLowerCase();
}

/// Строит маршрут каскада из адресов, введённых владельцем.
///
/// Пустой адрес оставляет станцию в [CascadeHopState.idle]; [stage] задаёт
/// состояние туннеля, [pingMs]/[updatedAt] — блок статуса.
CascadeRoute cascadeRouteFromAddresses({
  required String bridge,
  required String exit,
  CascadeStage stage = CascadeStage.idle,
  int? pingMs,
  DateTime? updatedAt,
}) {
  final bridgeHost = validateCascadeBridge(bridge);
  final exitHost = validateCascadeExit(exit);
  final configured = bridgeHost != null && exitHost != null;
  final hopState = configured
      ? (stage == CascadeStage.active
            ? CascadeHopState.connected
            : CascadeHopState.idle)
      : CascadeHopState.idle;
  return CascadeRoute(
    device: const CascadeHop(
      countryCode: '',
      label: 'Устройство',
      address: 'IPv4',
      state: CascadeHopState.connected,
    ),
    bridge: CascadeHop(
      countryCode: '',
      label: 'Bridge',
      address: bridgeHost ?? 'не настроен',
      state: hopState,
    ),
    exit: CascadeHop(
      countryCode: '',
      label: 'Exit',
      address: exitHost ?? 'не настроен',
      state: hopState,
    ),
    stage: configured ? stage : CascadeStage.idle,
    pingMs: configured ? pingMs : null,
    updatedAt: updatedAt,
  );
}
