/// SSH-проверка каскада с экрана «Каскад».
///
/// Экран не изобретает статус: он открывает SSH к сохранённому managed-серверу
/// и запускает на нём healthcheck. Приоритет — настоящий
/// `deploy/cascade/cascade-healthcheck.sh` (если он установлен); иначе
/// выполняется встроенная read-only проба systemd-каскада, которая печатает ту
/// же JSON-схему и добавляет реальный выходной IPv6 (`egress6`).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'cascade_health.dart';
import 'core.dart';
import 'credentials.dart';

/// Находит managed-сервер для проверки каскада.
///
/// Сначала точное совпадение SSH-хоста или VPN-адреса с bridge; если такого
/// нет — первый сохранённый сервер (владелец обычно держит один bridge).
ManagedServer? selectCascadeServer(
  Iterable<ManagedServer> servers,
  String bridgeAddress,
) {
  final list = servers.toList(growable: false);
  if (list.isEmpty) return null;
  final wanted = bridgeAddress.trim().toLowerCase();
  if (wanted.isNotEmpty) {
    for (final server in list) {
      if (server.host.toLowerCase() == wanted ||
          server.publicHost.toLowerCase() == wanted) {
        return server;
      }
    }
  }
  return list.first;
}

/// Проверка каскада по SSH на сохранённом сервере.
class CascadeSshProbe {
  CascadeSshProbe({
    required this.store,
    this.timeout = const Duration(seconds: 12),
  });

  final AppStore store;

  /// Таймаут одного SSH-вызова проверки; экран страхует его своим дедлайном.
  final Duration timeout;

  Future<CascadeHealth> check(String bridgeAddress) async {
    final clock = Stopwatch()..start();
    final server = selectCascadeServer(store.servers, bridgeAddress);
    if (server == null) {
      return CascadeHealth.failure(
        'Нет сохранённого сервера: добавьте bridge с SSH-доступом',
        latencyMs: clock.elapsedMilliseconds,
      );
    }
    final Map<String, String> saved;
    try {
      saved =
          await CredentialVault.read(store.credentialId(server)) ??
          const <String, String>{};
    } catch (_) {
      return CascadeHealth.failure(
        'Не удалось прочитать SSH-доступ к ${server.host}',
        latencyMs: clock.elapsedMilliseconds,
      );
    }
    if (saved.isEmpty) {
      return CascadeHealth.failure(
        'Для ${server.host} не сохранены SSH-учётные данные',
        latencyMs: clock.elapsedMilliseconds,
      );
    }
    final ssh = VpsService();
    try {
      await ssh
          .open(
            SshTarget(
              server.host,
              server.port,
              server.username,
              server.hostKey,
            ),
            saved['password'] ?? '',
            saved['key'] ?? '',
            saved['passphrase'] ?? '',
          )
          .timeout(timeout);
      final bytes = await ssh.executeInput(
        cascadeHealthCommand,
        const <int>[],
        timeout: timeout,
      );
      return CascadeHealth.parse(
        utf8.decode(bytes, allowMalformed: true),
        latencyMs: clock.elapsedMilliseconds,
      );
    } on TimeoutException {
      return CascadeHealth.failure(
        'Сервер ${server.host} не ответил за ${timeout.inSeconds} с',
        latencyMs: clock.elapsedMilliseconds,
      );
    } on StateError catch (error) {
      return CascadeHealth.failure(
        error.message,
        latencyMs: clock.elapsedMilliseconds,
      );
    } on FormatException catch (error) {
      return CascadeHealth.failure(
        error.message,
        latencyMs: clock.elapsedMilliseconds,
      );
    } on SocketException {
      return CascadeHealth.failure(
        'Нет SSH-соединения с ${server.host}',
        latencyMs: clock.elapsedMilliseconds,
      );
    } catch (_) {
      // Текст исключения SSH-библиотеки может содержать служебные детали —
      // наружу отдаём только адрес.
      return CascadeHealth.failure(
        'Не удалось проверить каскад по SSH на ${server.host}',
        latencyMs: clock.elapsedMilliseconds,
      );
    } finally {
      try {
        await ssh.close();
      } catch (_) {
        // Сессия всё равно закрывается; ошибка закрытия не влияет на вердикт.
      }
    }
  }
}

/// Один SSH-вызов проверки.
///
/// 1. Если на сервере установлен `cascade-healthcheck.sh` — запускается он
///    (`--role bridge --json-strict`, JSON в stdout).
/// 2. Если скрипт не применим (например, docker-схема не используется) —
///    встроенная проба: systemd-юнит, `tun0`, IPv6-маршрут по умолчанию и
///    реальный выходной IPv6 через `curl -6`.
///
/// Команда только читает состояние: ничего не перезапускает и не меняет.
const String cascadeHealthCommand = r'''
python3 - <<'XIO_CASCADE_HEALTH'
import json, os, re, subprocess, time


def run(args, timeout=12):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None


def add(checks, name, ok, detail):
    checks.append({'name': name, 'ok': bool(ok), 'detail': str(detail)[:300]})


checks = []
gateway = ''
script = None
for candidate in (
        '/opt/xio-cascade/cascade-healthcheck.sh',
        '/root/xio-cascade/cascade-healthcheck.sh',
        '/root/cascade/cascade-healthcheck.sh',
        '/usr/local/sbin/cascade-healthcheck.sh'):
    if os.path.isfile(candidate):
        script = candidate
        break

base = None
if script:
    answer = run(['bash', script, '--role', 'bridge', '--json-strict'])
    text = (answer.stdout or '') if answer else ''
    start, end = text.find('{'), text.rfind('}')
    if start >= 0 and end > start:
        try:
            parsed = json.loads(text[start:end + 1])
            if isinstance(parsed, dict) and parsed.get('checks'):
                base = parsed
        except ValueError:
            base = None

if base is not None:
    checks = [item for item in base.get('checks', []) if isinstance(item, dict)]
    gateway = str(base.get('exit_host') or '')
else:
    if script:
        add(checks, 'probe.source', True,
            'healthcheck ' + script + ' не применим здесь; встроенная проба')
    service = run(['systemctl', 'is-active', 'xio-cascade'])
    state = (service.stdout or '').strip() if service else 'unknown'
    add(checks, 'bridge.service', state == 'active',
        'systemd xio-cascade: ' + state)
    link = run(['ip', '-o', 'link', 'show', 'tun0'])
    tun_up = bool(link and link.returncode == 0 and 'UP' in (link.stdout or ''))
    add(checks, 'bridge.tunnel', tun_up,
        'tun0 ' + ('поднят' if tun_up else 'не существует'))
    route = run(['ip', '-6', 'route', 'show', 'default'])
    route_text = (route.stdout or '').strip() if route else ''
    match = re.search(r'default\s+via\s+([0-9a-fA-F:]+)', route_text)
    if match:
        gateway = match.group(1)
    add(checks, 'bridge.exit_route', bool(gateway),
        'IPv6 по умолчанию: ' + (route_text or 'нет'))

egress = ''
for url in ('https://ifconfig.co/ip', 'https://api64.ipify.org'):
    answer = run(['curl', '-6', '-sS', '--max-time', '6', url], timeout=8)
    if answer and answer.returncode == 0:
        candidate = (answer.stdout or '').strip()
        if ':' in candidate:
            egress = candidate
            break

# Настоящий healthcheck сам решает, жив ли каскад: наш egress — дополнение к
# его ответу, а не ещё один голос в вердикте. Встроенная проба, наоборот,
# считает egress такой же обязательной проверкой, как tun0 и маршрут.
if base is None:
    add(checks, 'exit.egress6', ':' in egress,
        'выходной IPv6: ' + (egress if ':' in egress
                            else 'нет ответа по IPv6 (curl/timeout)'))

print(json.dumps({
    'ok': bool(base.get('ok')) if base is not None
          else all(bool(item.get('ok')) for item in checks),
    'role': str((base or {}).get('role') or 'bridge'),
    'runtime': str((base or {}).get('runtime') or 'systemd'),
    'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'exit_host': gateway,
    'egress6': egress if ':' in egress else '',
    'checks': checks,
}, ensure_ascii=False))
XIO_CASCADE_HEALTH
''';
