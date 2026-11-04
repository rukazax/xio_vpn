import 'package:flutter_test/flutter_test.dart';
import 'package:xio/cascade_health.dart';
import 'package:xio/cascade_model.dart';

/// Полный ответ `deploy/cascade/cascade-healthcheck.sh`: все проверки прошли,
/// выходной IPv6 есть только в detail проверки `exit.egress6`.
const String _healthyHealthcheck = '''
[health] ok  bridge.container: xio-cascade-bridge запущен
{"ok": true, "role": "bridge", "time": "2026-11-04T20:41:07Z",
 "runtime": "docker", "exit_host": "2a0c:b641:1a0:800::2a2",
 "checks": [
   {"name": "bridge.container", "ok": true, "detail": "xio-cascade-bridge запущен"},
   {"name": "bridge.tunnel", "ok": true, "detail": "интерфейсы wg0 и wg1 подняты"},
   {"name": "bridge.exit_route", "ok": true, "detail": "маршрут до [2a0c:b641:1a0:800::2a2] есть"},
   {"name": "bridge.handshake", "ok": true, "detail": "рукопожатие 12с назад"},
   {"name": "exit.egress6", "ok": true, "detail": "выходной IPv6: 2a0c:b641:1a0:800::9a9"}
 ]}
''';

const String _degradedHealthcheck = '''
{"ok": false, "role": "bridge", "runtime": "systemd",
 "checks": [
   {"name": "bridge.tunnel", "ok": true, "detail": "tun0 поднят"},
   {"name": "bridge.exit_route", "ok": true, "detail": "маршрут есть"},
   {"name": "exit.egress6", "ok": true, "detail": "выходной IPv6: 2a0c:b641:1a0:800::9a9"},
   {"name": "bridge.whitelist", "ok": false, "detail": "нет сета xio_whitelist4"}
 ]}
''';

const String _bridgeDown = '''
{"ok": false, "role": "bridge", "runtime": "docker",
 "checks": [
   {"name": "bridge.container", "ok": false, "detail": "контейнер xio-cascade-bridge не запущен"},
   {"name": "bridge.tunnel", "ok": false, "detail": "не все интерфейсы подняты"}
 ]}
''';

const String _exitBroken = '''
{"ok": false, "role": "bridge", "runtime": "systemd",
 "checks": [
   {"name": "bridge.tunnel", "ok": true, "detail": "tun0 поднят"},
   {"name": "bridge.exit_route", "ok": true, "detail": "маршрут есть"},
   {"name": "bridge.handshake", "ok": false, "detail": "рукопожатия не было — туннель до exit не установлен"}
 ]}
''';

void main() {
  group('Успешная проверка', () {
    test('живой каскад: стадия active, пинг, egress из detail', () {
      final health = CascadeHealth.parse(
        _healthyHealthcheck,
        latencyMs: 812,
        now: DateTime.utc(2026, 11, 4, 20, 41, 7),
      );
      expect(health.verdict, CascadeHealthVerdict.ok);
      expect(health.ok, isTrue);
      expect(health.alive, isTrue);
      expect(health.stage, CascadeStage.active);
      expect(health.bridgeState, CascadeHopState.connected);
      expect(health.exitState, CascadeHopState.connected);
      expect(health.latencyMs, 812);
      expect(health.egressIpv6, '2a0c:b641:1a0:800::9a9');
      expect(health.exitHost, '2a0c:b641:1a0:800::2a2');
      expect(health.role, 'bridge');
      expect(health.runtime, 'docker');
      expect(health.checkedAt, DateTime.utc(2026, 11, 4, 20, 41, 7));
      expect(health.reason, isNull);
      expect(health.caption(), contains('только IPv6'));
      expect(health.checks, hasLength(5));
    });

    test('JSON без checks: доверяем ok, egress берём из ответа', () {
      final health = CascadeHealth.parse('''
{"ok": true, "egress6": "2a0c:b641:1a0:800::9a9"}
''');
      expect(health.ok, isTrue);
      expect(health.stage, CascadeStage.active);
      expect(health.egressIpv6, '2a0c:b641:1a0:800::9a9');
    });

    test('формат dualstack.cascade_status(): alive=true', () {
      final health = CascadeHealth.parse(
        '{"alive": true, "reason": "ok", "probe": "ping+tcp", "checkedAt": 1}',
      );
      expect(health.verdict, CascadeHealthVerdict.ok);
      expect(health.stage, CascadeStage.active);
      expect(health.reason, isNull);
      expect(health.egressIpv6, isNull);
    });

    test('реальный ответ встроенной пробы bridge 81.177.142.37', () {
      // Дословный stdout пробы на живом bridge (04.11.2026, systemd-каскад).
      final health = CascadeHealth.parse('''
{"ok": true, "role": "bridge", "runtime": "systemd", "time": "2026-11-04T20:33:02Z",
 "exit_host": "fd00:201::2", "egress6": "2a0c:b641:1a0:800::2a2",
 "checks": [
  {"name": "bridge.service", "ok": true, "detail": "systemd xio-cascade: active"},
  {"name": "bridge.tunnel", "ok": true, "detail": "tun0 поднят"},
  {"name": "bridge.exit_route", "ok": true, "detail": "IPv6 по умолчанию: default via fd00:201::2 dev tun0 metric 1024 pref medium"},
  {"name": "exit.egress6", "ok": true, "detail": "выходной IPv6: 2a0c:b641:1a0:800::2a2"}
 ]}
''', latencyMs: 640);
      expect(health.verdict, CascadeHealthVerdict.ok);
      expect(health.stage, CascadeStage.active);
      expect(health.egressIpv6, '2a0c:b641:1a0:800::2a2');
      expect(health.exitHost, 'fd00:201::2');
      expect(health.latencyMs, 640);
      expect(health.checks, hasLength(4));
    });
  });

  group('Деградация', () {
    test('провал только whitelist — каскад жив с замечаниями', () {
      final health = CascadeHealth.parse(_degradedHealthcheck);
      expect(health.verdict, CascadeHealthVerdict.degraded);
      expect(health.alive, isTrue);
      expect(health.stage, CascadeStage.degraded);
      expect(health.bridgeState, CascadeHopState.degraded);
      expect(health.exitState, CascadeHopState.degraded);
      expect(health.reason, 'нет сета xio_whitelist4');
      expect(health.caption(), contains('замечаниями'));
    });
  });

  group('Отказ', () {
    test('bridge не запущен — failed без выдуманного bridgeToExit', () {
      final health = CascadeHealth.parse(_bridgeDown);
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.alive, isFalse);
      expect(health.stage, CascadeStage.failed);
      expect(health.bridgeState, CascadeHopState.failed);
      expect(health.exitState, CascadeHopState.idle);
      expect(health.reason, 'контейнер xio-cascade-bridge не запущен');
      expect(health.caption(), contains('не построен'));
    });

    test('bridge жив, exit нет — стадия bridge → exit', () {
      final health = CascadeHealth.parse(_exitBroken);
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.stage, CascadeStage.bridgeToExit);
      expect(health.bridgeState, CascadeHopState.connected);
      expect(health.exitState, CascadeHopState.failed);
      expect(health.caption(), startsWith('Bridge → Exit · '));
    });

    test('healthcheck вернул ошибку без проверок', () {
      final health = CascadeHealth.parse(
        '{"ok": false, "error": "не найден рабочий docker/podman", "checks": []}',
      );
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.reason, 'не найден рабочий docker/podman');
      expect(health.stage, CascadeStage.failed);
    });

    test('dualstack: нет IPv6-маршрута — причина по-русски', () {
      final health = CascadeHealth.parse(
        '{"alive": false, "reason": "no-ipv6-default-route", "probe": "route"}',
      );
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.alive, isFalse);
      expect(health.reason, contains('IPv6-маршрута'));
    });

    test('CascadeHealth.failure сохраняет измеренный отклик', () {
      final health = CascadeHealth.failure('Нет SSH', latencyMs: 17);
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.reason, 'Нет SSH');
      expect(health.latencyMs, 17);
      expect(health.caption(), contains('Нет SSH'));
    });

    test('CascadeHealth.unconfigured — честное «не настроен»', () {
      final health = CascadeHealth.unconfigured();
      expect(health.verdict, CascadeHealthVerdict.unconfigured);
      expect(health.stage, CascadeStage.idle);
      expect(health.bridgeState, CascadeHopState.idle);
      expect(health.exitState, CascadeHopState.idle);
      expect(health.caption(), contains('не настроен'));
    });
  });

  group('Мусор вместо JSON', () {
    final garbage = <String, String>{
      'пустой ответ': '',
      'HTML вместо JSON': '<html><body>502 Bad Gateway</body></html>',
      'обрезанный JSON': '{"ok": true, "checks": [',
      'массив вместо объекта': '[{"ok": true}]',
      'нет полей ok/alive': '{"checks": []}',
      'ok строкой': '{"ok": "yes", "checks": []}',
      'alive числом': '{"alive": 1}',
    };
    for (final entry in garbage.entries) {
      test('${entry.key} → failed с причиной', () {
        final health = CascadeHealth.parse(entry.value);
        expect(health.verdict, CascadeHealthVerdict.failed, reason: entry.key);
        expect(health.alive, isFalse, reason: entry.key);
        expect(health.stage, isNot(CascadeStage.active));
        expect(health.reason, isNotNull, reason: entry.key);
        expect(health.reason, isNotEmpty, reason: entry.key);
        expect(health.egressIpv6, isNull, reason: entry.key);
      });
    }

    test('мусорные элементы checks пропускаются, валидные читаются', () {
      final health = CascadeHealth.parse('''
{"ok": false, "checks": [
  null, "строка", {"name": "", "ok": true}, {"ok": true},
  {"name": "exit.egress6", "ok": false, "detail": "нет ответа по IPv6 (curl/timeout)"}
]}
''');
      expect(health.checks, hasLength(1));
      expect(health.checks.single.name, 'exit.egress6');
      expect(health.verdict, CascadeHealthVerdict.failed);
      expect(health.reason, 'нет ответа по IPv6 (curl/timeout)');
      expect(health.egressIpv6, isNull);
    });

    test('checks не список — ответ всё равно читается по ok', () {
      final health = CascadeHealth.parse('{"ok": true, "checks": "мусор"}');
      expect(health.ok, isTrue);
      expect(health.checks, isEmpty);
    });
  });

  group('Выходной IPv6', () {
    test('глобальный IPv6 из проверки exit.ipv6', () {
      final health = CascadeHealth.parse('''
{"ok": true, "checks": [
  {"name": "exit.ipv6", "ok": true, "detail": "глобальный IPv6: fd00:201::1"}
]}
''');
      expect(health.egressIpv6, 'fd00:201::1');
    });

    test('проваленная проверка egress не даёт адрес', () {
      final health = CascadeHealth.parse('''
{"ok": false, "checks": [
  {"name": "exit.egress6", "ok": false, "detail": "выходной IPv6: 2a0c:b641:1a0:800::9a9"}
]}
''');
      expect(health.egressIpv6, isNull);
    });

    test('мусор в поле egress6 игнорируется', () {
      final health = CascadeHealth.parse(
        '{"ok": true, "egress6": "нет ответа"}',
      );
      expect(health.egressIpv6, isNull);
    });
  });
}
