/// Разбор JSON реальной проверки каскада и перевод его в стадии экрана.
///
/// Источник данных — `deploy/cascade/cascade-healthcheck.sh` на bridge-сервере
/// (`{"ok": bool, "role": ..., "checks": [...]}`) либо встроенная read-only
/// проба systemd-каскада, которая печатает ту же схему плюс `egress6`.
/// Файл намеренно не импортирует Flutter: разбор используется и экраном, и
/// обычными unit-тестами.
library;

import 'dart:convert';

import 'cascade_model.dart';

/// Вызов реальной проверки: bridge-адрес из настроек → результат.
typedef CascadeHealthProbe = Future<CascadeHealth> Function(
  String bridgeAddress,
);

/// Один пункт проверки из массива `checks[]`.
class CascadeHealthCheck {
  const CascadeHealthCheck({
    required this.name,
    required this.ok,
    this.detail = '',
  });

  /// Машинное имя проверки (`bridge.tunnel`, `exit.egress6`, ...).
  final String name;

  /// Прошла ли проверка.
  final bool ok;

  /// Человекочитаемая подробность; сервер уже отредактировал её.
  final String detail;

  /// Терпимый разбор одного элемента `checks[]`: всё, что не похоже на
  /// проверку, отбрасывается, а не роняет весь ответ.
  static CascadeHealthCheck? tryParse(Object? json) {
    if (json is! Map) return null;
    final name = json['name'];
    if (name is! String || name.trim().isEmpty) return null;
    final detail = json['detail'];
    return CascadeHealthCheck(
      name: name.trim(),
      ok: json['ok'] == true,
      detail: detail is String ? detail.trim() : '',
    );
  }

  @override
  String toString() => '$name:${ok ? 'ok' : 'fail'}';
}

/// Итог проверки каскада.
enum CascadeHealthVerdict {
  /// Все проверки прошли.
  ok,

  /// Каскад жив, но есть некритичное замечание (например, нет nft-сета
  /// белых списков split-tunneling).
  degraded,

  /// Каскад не построен либо ответ не разобран.
  failed,

  /// Адреса каскада не заданы — проверять нечего.
  unconfigured,
}

/// Результат реального опроса каскада.
class CascadeHealth {
  const CascadeHealth({
    required this.verdict,
    required this.checkedAt,
    this.latencyMs,
    this.role = '',
    this.runtime = '',
    this.exitHost,
    this.egressIpv6,
    this.error,
    this.checks = const <CascadeHealthCheck>[],
  });

  /// Каскада нет: bridge и exit не заданы.
  factory CascadeHealth.unconfigured({DateTime? now}) => CascadeHealth(
    verdict: CascadeHealthVerdict.unconfigured,
    checkedAt: now ?? DateTime.now(),
    error: 'Каскад не настроен: укажите bridge и exit',
  );

  /// Проверка не состоялась (нет сервера, SSH, таймаут, мусор вместо JSON).
  factory CascadeHealth.failure(
    String message, {
    int? latencyMs,
    DateTime? now,
  }) => CascadeHealth(
    verdict: CascadeHealthVerdict.failed,
    checkedAt: now ?? DateTime.now(),
    latencyMs: latencyMs,
    error: message,
  );

  final CascadeHealthVerdict verdict;

  /// Когда проверка завершилась (локальное время).
  final DateTime checkedAt;

  /// Время ответа: полный round-trip SSH-команды проверки, мс.
  final int? latencyMs;

  /// `role` из JSON (`bridge`, `exit`, `both`).
  final String role;

  /// `runtime` из JSON (`docker`, `podman`, `systemd`).
  final String runtime;

  /// IPv6 exit-сервера, если сервер его сообщил.
  final String? exitHost;

  /// Реальный выходной IPv6 (тот, что видит внешний сервис), если известен.
  final String? egressIpv6;

  /// Причина отказа/замечания — текст для пользователя.
  final String? error;

  /// Пункты проверки в порядке, присланном сервером.
  final List<CascadeHealthCheck> checks;

  bool get ok => verdict == CascadeHealthVerdict.ok;

  /// Каскад жив: полностью или с замечаниями.
  bool get alive =>
      verdict == CascadeHealthVerdict.ok ||
      verdict == CascadeHealthVerdict.degraded;

  /// Проваленные проверки.
  List<CascadeHealthCheck> get failures =>
      checks.where((check) => !check.ok).toList(growable: false);

  /// Понятная причина: явный `error`, иначе первый провал.
  String? get reason {
    final explicit = error?.trim();
    if (explicit != null && explicit.isNotEmpty) return explicit;
    for (final failure in failures) {
      if (failure.detail.isNotEmpty) return failure.detail;
      return failure.name;
    }
    return null;
  }

  /// Стадия схемы по результату опроса. `deviceToBridge` экран показывает
  /// только пока запрос действительно выполняется.
  CascadeStage get stage => switch (verdict) {
    CascadeHealthVerdict.ok => CascadeStage.active,
    CascadeHealthVerdict.degraded => CascadeStage.degraded,
    CascadeHealthVerdict.unconfigured => CascadeStage.idle,
    CascadeHealthVerdict.failed =>
      _bridgeAlive && _exitBroken
          ? CascadeStage.bridgeToExit
          : CascadeStage.failed,
  };

  /// Bridge ответил: проверки самого хоста `bridge.*` не провалены.
  ///
  /// `bridge.handshake`, `bridge.exit_route` и `bridge.whitelist` описывают
  /// не сам bridge, а связь за ним, поэтому в «bridge жив» не входят.
  bool get _bridgeAlive {
    const core = <String>{
      'bridge.container',
      'bridge.tunnel',
      'bridge.service',
    };
    final host = checks.where((check) => core.contains(check.name));
    if (host.isNotEmpty) return host.every((check) => check.ok);
    final bridge = checks.where(
      (check) =>
          check.name.startsWith('bridge.') &&
          check.name != 'bridge.handshake' &&
          check.name != 'bridge.exit_route' &&
          check.name != 'bridge.whitelist',
    );
    if (bridge.isEmpty) return checks.isNotEmpty;
    return bridge.every((check) => check.ok);
  }

  /// Провалилась часть за bridge-ом: выходной туннель, exit или egress.
  bool get _exitBroken => checks.any(
    (check) =>
        !check.ok &&
        (check.name.startsWith('exit.') ||
            check.name.startsWith('bridge.exit') ||
            check.name.startsWith('bridge.handshake')),
  );

  CascadeHopState get bridgeState => switch (verdict) {
    CascadeHealthVerdict.ok => CascadeHopState.connected,
    CascadeHealthVerdict.degraded => CascadeHopState.degraded,
    CascadeHealthVerdict.unconfigured => CascadeHopState.idle,
    CascadeHealthVerdict.failed =>
      _bridgeAlive ? CascadeHopState.connected : CascadeHopState.failed,
  };

  CascadeHopState get exitState => switch (verdict) {
    CascadeHealthVerdict.ok => CascadeHopState.connected,
    CascadeHealthVerdict.degraded => CascadeHopState.degraded,
    CascadeHealthVerdict.unconfigured => CascadeHopState.idle,
    CascadeHealthVerdict.failed =>
      _bridgeAlive && _exitBroken
          ? CascadeHopState.failed
          : CascadeHopState.idle,
  };

  /// Подпись под схемой: никогда не выдаёт желаемое за действительное.
  String caption() {
    switch (verdict) {
      case CascadeHealthVerdict.ok:
        return 'Защищённый туннель только IPv6 · проверено';
      case CascadeHealthVerdict.degraded:
        return 'Каскад жив с замечаниями · ${_short(reason)}';
      case CascadeHealthVerdict.unconfigured:
        return 'Каскад не настроен · укажите серверы';
      case CascadeHealthVerdict.failed:
        final why = _short(reason);
        return stage == CascadeStage.bridgeToExit
            ? 'Bridge → Exit · $why'
            : 'Каскад не построен · $why';
    }
  }

  /// Разбор stdout healthcheck-а. Никогда не бросает: мусор превращается в
  /// вердикт [CascadeHealthVerdict.failed] с понятной причиной.
  factory CascadeHealth.parse(String output, {int? latencyMs, DateTime? now}) {
    final checkedAt = now ?? DateTime.now();
    final raw = output.trim();
    final start = raw.indexOf('{');
    final end = raw.lastIndexOf('}');
    if (start < 0 || end <= start) {
      return CascadeHealth.failure(
        'Сервер не вернул JSON о каскаде',
        latencyMs: latencyMs,
        now: checkedAt,
      );
    }
    // Массив объектов — не ответ healthcheck-а; не выдёргиваем из него первый
    // объект, иначе мусор прошёл бы за валидный статус.
    if (raw.substring(0, start).trimRight().endsWith('[')) {
      return CascadeHealth.failure(
        'Ожидался JSON-объект, а пришёл массив',
        latencyMs: latencyMs,
        now: checkedAt,
      );
    }
    Object? decoded;
    try {
      decoded = jsonDecode(raw.substring(start, end + 1));
    } on FormatException {
      decoded = null;
    }
    if (decoded is! Map) {
      return CascadeHealth.failure(
        'Некорректный JSON от healthcheck',
        latencyMs: latencyMs,
        now: checkedAt,
      );
    }
    final map = <String, Object?>{};
    decoded.forEach((key, value) {
      if (key is String) map[key] = value;
    });
    final hasOk = map.containsKey('ok');
    final hasAlive = map.containsKey('alive');
    if (!hasOk && !hasAlive) {
      return CascadeHealth.failure(
        'В ответе нет поля ok/alive',
        latencyMs: latencyMs,
        now: checkedAt,
      );
    }
    if ((hasOk && map['ok'] is! bool) || (hasAlive && map['alive'] is! bool)) {
      return CascadeHealth.failure(
        'Некорректное поле ok/alive в ответе',
        latencyMs: latencyMs,
        now: checkedAt,
      );
    }
    final checks = <CascadeHealthCheck>[];
    final reported = map['checks'];
    if (reported is List) {
      for (final item in reported) {
        final parsed = CascadeHealthCheck.tryParse(item);
        if (parsed != null) checks.add(parsed);
      }
    }
    final reportedOk = hasOk ? map['ok'] as bool : true;
    final alive = hasAlive ? map['alive'] as bool : true;
    final everythingOk = reportedOk && alive;
    final failures = checks.where((check) => !check.ok).toList(growable: false);
    final error = _reasonText(_firstString(map, const ['error', 'reason']));
    final verdict = _verdict(
      everythingOk: everythingOk,
      checks: checks,
      failures: failures,
    );
    return CascadeHealth(
      verdict: verdict,
      checkedAt: checkedAt,
      latencyMs: latencyMs,
      role: _firstString(map, const ['role']) ?? '',
      runtime: _firstString(map, const ['runtime']) ?? '',
      exitHost: _firstString(map, const ['exit_host', 'exitHost']),
      egressIpv6: _findEgress(map, checks),
      error: error,
      checks: checks,
    );
  }

  static CascadeHealthVerdict _verdict({
    required bool everythingOk,
    required List<CascadeHealthCheck> checks,
    required List<CascadeHealthCheck> failures,
  }) {
    if (everythingOk) return CascadeHealthVerdict.ok;
    if (checks.isEmpty) return CascadeHealthVerdict.failed;
    // Замечание, которое не рвёт туннель: split-tunneling без nft-сета.
    if (failures.isNotEmpty &&
        failures.every((check) => check.name.contains('whitelist'))) {
      return CascadeHealthVerdict.degraded;
    }
    return CascadeHealthVerdict.failed;
  }

  /// Короткий текст причины: подпись не должна разрастаться на пол-экрана.
  static String _short(String? reason, [int max = 72]) {
    final text = (reason ?? '').trim();
    if (text.isEmpty) return 'проверка не прошла';
    if (text.length <= max) return text;
    return '${text.substring(0, max - 1)}…';
  }

  /// Первая непустая строка из списка ключей.
  static String? _firstString(Map<String, Object?> map, List<String> keys) {
    for (final key in keys) {
      final value = map[key];
      if (value is String && value.trim().isNotEmpty) return value.trim();
    }
    return null;
  }

  /// Коды `dualstack.cascade_status()` и ошибки healthcheck-а по-русски.
  static String? _reasonText(String? raw) {
    if (raw == null) return null;
    return switch (raw) {
      'no-ipv6-default-route' =>
        'нет IPv6-маршрута по умолчанию: туннель bridge → exit не поднят',
      'cascade-down' => 'exit не отвечает по IPv6',
      'probe-error' => 'проба IPv6 завершилась ошибкой',
      'ok' => null,
      _ => raw,
    };
  }

  /// Реальный выходной IPv6: отдельное поле ответа либо detail проверки.
  static String? _findEgress(
    Map<String, Object?> map,
    List<CascadeHealthCheck> checks,
  ) {
    for (final key in const <String>[
      'egress6',
      'egress',
      'output6',
      'outputIpv6',
      'egressIpv6',
    ]) {
      final value = map[key];
      final found = value is String ? _ipv6In(value) : null;
      if (found != null) return found;
    }
    for (final check in checks) {
      if (!check.ok) continue;
      final name = check.name.toLowerCase();
      if (!name.contains('egress') && !name.endsWith('.ipv6')) continue;
      final found = _ipv6In(check.detail);
      if (found != null) return found;
    }
    return null;
  }

  static final RegExp _addressToken = RegExp(r'[0-9A-Fa-f:]{2,45}');

  /// Первый IPv6-адрес в произвольной строке (`выходной IPv6: 2a0c:…`).
  ///
  /// Берём подряд идущие hex-символы и двоеточия и проверяем группу вручную:
  /// так «6:» из слова `IPv6:` и время `20:41:07` не выдаются за адрес.
  static String? _ipv6In(String text) {
    for (final match in _addressToken.allMatches(text)) {
      final candidate = match.group(0)!;
      if (_validIpv6(candidate)) return candidate;
    }
    return null;
  }

  static bool _validIpv6(String value) {
    if (!value.contains(':')) return false;
    if ('::'.allMatches(value).length > 1) return false;
    var groups = 0;
    for (final section in value.split(':')) {
      if (section.isEmpty) continue;
      if (!RegExp(r'^[0-9A-Fa-f]{1,4}$').hasMatch(section)) return false;
      groups++;
    }
    // Без «::» IPv6 состоит ровно из восьми групп; «::» сжимает хотя бы одну.
    return value.contains('::') ? groups <= 7 : groups == 8;
  }

  @override
  String toString() => 'CascadeHealth(${verdict.name}, ${latencyMs}ms)';
}
