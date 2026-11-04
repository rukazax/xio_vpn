/// Ссылка MTProto-прокси, выданная сервером, и установка прокси по SSH.
///
/// Ссылку не вводит оператор: её знает сервер (`/etc/xio-mtproto/secret`,
/// `port`, `domain`) и отдаёт через `admin.py` действием `mtproto`. Приложение
/// спрашивает её само при настройке сервера, после добавления пользователя и
/// при открытии экрана «Telegram-прокси»; формат ссылки проверяет
/// [parseMtprotoLink].
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'cascade_probe.dart' show selectCascadeServer;
import 'core.dart';
import 'credentials.dart';

/// Ответ сервера на `{"action":"mtproto"}`.
///
/// Прокси может быть не установлен — это не ошибка: экран предложит кнопку
/// установки. А вот установленный прокси без рабочей ссылки — ошибка сервера:
/// такую ссылку нельзя ни показать, ни отдать в Telegram.
class MtprotoServerState {
  const MtprotoServerState({
    required this.installed,
    required this.host,
    required this.port,
    this.link,
  });

  /// `true`, если на сервере есть рабочий FakeTLS-секрет.
  final bool installed;

  /// Адрес из `/etc/xio-mtproto/domain` (или VPN-адрес сервера).
  final String host;

  /// Порт из `/etc/xio-mtproto/port` (по умолчанию 8444).
  final int port;

  /// Каноническая ссылка `tg://proxy?…` или `null`, если прокси не установлен.
  final MtprotoProxyLink? link;

  /// Разбор ответа `admin.py`. Числа приходят как int, но сервер мог отдать
  /// строку — принимаем оба вида и дальше проверяем диапазон.
  factory MtprotoServerState.parse(Object? raw) {
    if (raw is! Map) {
      throw const FormatException('Сервер вернул некорректный ответ MTProto');
    }
    final portRaw = raw['port'];
    final port = portRaw is int
        ? portRaw
        : int.tryParse('${portRaw ?? ''}') ?? 0;
    if (port < 1 || port > 65535) {
      throw const FormatException('Сервер вернул некорректный порт MTProto');
    }
    final hostRaw = raw['host'];
    final host = hostRaw is String ? hostRaw.trim() : '';
    if (raw['installed'] != true) {
      return MtprotoServerState(
        installed: false,
        host: host,
        port: port,
      );
    }
    final linkRaw = raw['link'];
    if (linkRaw is! String) {
      throw const FormatException('Сервер не вернул ссылку MTProto');
    }
    final parsed = parseMtprotoLink(linkRaw);
    if (parsed == null) {
      throw const FormatException('Сервер вернул некорректную ссылку MTProto');
    }
    return MtprotoServerState(
      installed: true,
      host: host.isEmpty ? parsed.server : host,
      port: port,
      link: parsed,
    );
  }
}

/// Что нужно экрану «Telegram-прокси» от сервера. Отдельный интерфейс, чтобы
/// экран проверялся тестом без настоящего SSH.
abstract class MtprotoRemote {
  /// Состояние прокси на сервере.
  Future<MtprotoServerState> fetch();

  /// Ставит прокси установщиком из репозитория и возвращает хвост его лога.
  Future<String> install();
}

/// Read-only запрос: тот же stdin-протокол `admin.py`, что у `status`.
const String mtprotoProbeCommand = 'python3 /usr/local/lib/xio-managed/admin.py';

/// Установка скриптом из репозитория — так же, как каскадный установщик.
/// `curl -fsSL … | bash` заменён на скачивание с проверкой кода возврата,
/// иначе ошибка curl выглядела бы как ошибка bash.
const String mtprotoInstallCommand =
    'url=https://raw.githubusercontent.com/rukazax/xio_vpn/main/deploy/mtproto/xio-mtproto-setup.sh; '
    'curl -fsSL "\$url" -o /tmp/xio-mtproto-setup.sh && '
    'bash /tmp/xio-mtproto-setup.sh >/var/log/xio-mtproto-install.log 2>&1; '
    'rc=\$?; tail -8 /var/log/xio-mtproto-install.log 2>/dev/null; '
    'echo "XIO_MTINSTALL_RC=\$rc"; exit \$rc';

/// Запрос ссылки и установка прокси по SSH на managed-сервере.
class SshMtprotoRemote implements MtprotoRemote {
  SshMtprotoRemote({
    required this.store,
    this.timeout = const Duration(seconds: 10),
    this.installTimeout = const Duration(minutes: 10),
  });

  final AppStore store;

  /// Дедлайн одного запроса ссылки; экран страхует его своим ожиданием.
  final Duration timeout;

  /// Установка качает бинарь mtg, поэтому её дедлайн измеряется минутами.
  final Duration installTimeout;

  /// Сервер, на котором живёт прокси: точное совпадение с bridge каскада,
  /// иначе первый сохранённый — владелец обычно держит один bridge.
  ManagedServer? get server =>
      selectCascadeServer(store.servers, store.cascadeBridge);

  @override
  Future<MtprotoServerState> fetch() async {
    final target = server;
    if (target == null) {
      throw StateError('Нет сохранённого сервера: добавьте сервер по SSH');
    }
    final ssh = await _connect(target);
    try {
      final bytes = await ssh.executeInput(
        mtprotoProbeCommand,
        utf8.encode(jsonEncode({'action': 'mtproto'})),
        timeout: timeout,
      );
      final answer = _decode(bytes);
      if (answer['ok'] != true) {
        throw StateError(_serverError(answer['error']));
      }
      final state = MtprotoServerState.parse(answer);
      return state;
    } on TimeoutException {
      throw StateError(
        'Сервер ${target.host} не ответил за ${timeout.inSeconds} с',
      );
    } finally {
      try {
        await ssh.close();
      } catch (_) {
        // Сессия всё равно закрывается; ошибка закрытия не влияет на ответ.
      }
    }
  }

  @override
  Future<String> install() async {
    final target = server;
    if (target == null) {
      throw StateError('Нет сохранённого сервера: добавьте сервер по SSH');
    }
    final ssh = await _connect(target);
    try {
      final bytes = await ssh.executeInput(
        mtprotoInstallCommand,
        const <int>[],
        timeout: installTimeout,
      );
      final output = utf8.decode(bytes, allowMalformed: true).trim();
      final code = _installCode(output);
      if (code != null && code != 0) {
        final tail = output
            .split('\n')
            .where((line) => !line.startsWith('XIO_MTINSTALL_RC='))
            .where((line) => line.trim().isNotEmpty)
            .lastOrNull;
        throw StateError(
          tail == null
              ? 'Установщик MTProto завершился ошибкой (код $code)'
              : 'Установщик MTProto завершился ошибкой: $tail',
        );
      }
      return output;
    } on TimeoutException {
      throw StateError(
        'Установка не завершилась за ${installTimeout.inMinutes} мин. '
        'Проверьте сервер и повторите.',
      );
    } finally {
      try {
        await ssh.close();
      } catch (_) {
        // См. fetch(): закрытие сессии не влияет на результат.
      }
    }
  }

  Future<VpsService> _connect(ManagedServer target) async {
    final Map<String, String> saved;
    try {
      saved =
          await CredentialVault.read(store.credentialId(target)) ??
          const <String, String>{};
    } catch (_) {
      throw StateError('Не удалось прочитать SSH-доступ к ${target.host}');
    }
    if (saved.isEmpty) {
      throw StateError(
        'Для ${target.host} не сохранены SSH-учётные данные',
      );
    }
    final ssh = VpsService();
    try {
      await ssh
          .open(
            SshTarget(
              target.host,
              target.port,
              target.username,
              target.hostKey,
            ),
            saved['password'] ?? '',
            saved['key'] ?? '',
            saved['passphrase'] ?? '',
          )
          .timeout(timeout);
    } on TimeoutException {
      throw StateError(
        'Сервер ${target.host} не ответил за ${timeout.inSeconds} с',
      );
    } on SocketException {
      throw StateError('Нет SSH-соединения с ${target.host}');
    } catch (_) {
      // Текст исключения SSH-библиотеки может содержать служебные детали —
      // наружу отдаём только адрес.
      throw StateError('Не удалось подключиться по SSH к ${target.host}');
    }
    return ssh;
  }

  Map<String, dynamic> _decode(List<int> bytes) {
    try {
      final data = jsonDecode(utf8.decode(bytes, allowMalformed: true));
      if (data is Map) return Map<String, dynamic>.from(data);
    } on FormatException {
      // Ниже — одна понятная ошибка вместо текста парсера.
    }
    throw const FormatException('Сервер не вернул ответ MTProto');
  }

  String _serverError(Object? error) => switch (error) {
    'Operation not permitted' => 'Ссылка доступна только владельцу сервера',
    'root required' => 'Нужен SSH-доступ root',
    // Так отвечает серверная часть, в которой ещё нет действия `mtproto`:
    // запрос без serverId не проходит проверку идентичности установки.
    'Server identity changed; reopen setup' =>
      'Сервер не поддерживает запрос MTProto — обновите XIO на сервере',
    _ => 'Ошибка сервера MTProto',
  };

  int? _installCode(String output) {
    for (final line in output.split('\n').reversed) {
      if (line.startsWith('XIO_MTINSTALL_RC=')) {
        return int.tryParse(line.substring('XIO_MTINSTALL_RC='.length).trim());
      }
    }
    return null;
  }
}
