/// MTProto-прокси для Telegram: разбор и проверка ссылки `tg://proxy?…`.
///
/// Ссылку выдаёт сервер (`deploy/mtproto/xio-mtproto-setup.sh --print-link`)
/// или оператор прокси. Приложение её только хранит, показывает и передаёт
/// в Telegram: ни секрет, ни адрес не используются для собственного
/// подключения, поэтому здесь нет сетевого кода — только формат.
library;

import 'dart:convert';
import 'dart:io';

/// Разобранная ссылка на MTProto-прокси.
class MtprotoProxyLink {
  const MtprotoProxyLink({
    required this.server,
    required this.port,
    required this.secret,
  });

  /// Адрес прокси: IPv4, домен или IPv6 в квадратных скобках.
  final String server;

  /// TCP-порт прокси.
  final int port;

  /// Секрет прокси: hex (`ee…`/`dd…`) или base64 тех же байт.
  final String secret;

  /// Канонический вид ссылки — его и хранит приложение.
  ///
  /// Ссылка `https://t.me/proxy?…` из буфера обмена приводится к `tg://`,
  /// чтобы кнопки «Открыть в Telegram» и «Скопировать» давали один и тот же
  /// результат на всех платформах.
  String get link => 'tg://proxy?server=$server&port=$port&secret=$secret';

  /// Подпись для экрана: `сервер:порт`.
  String get address => '$server:$port';

  @override
  bool operator ==(Object other) =>
      other is MtprotoProxyLink && other.link == link;

  @override
  int get hashCode => link.hashCode;

  @override
  String toString() => link;
}

/// Проверка «как в Telegram»: принимаем оба вида ссылки и возвращаем
/// каноническую или `null`.
MtprotoProxyLink? parseMtprotoLink(String raw) => _check(raw).link;

/// Текст ошибки для формы или `null`, если ссылка корректна.
String? validateMtprotoLink(String raw) => _check(raw).error;

/// Параметры, которые Telegram понимает в MTProto-ссылке. Всё остальное
/// отклоняем: молча сохранённый мусор потом не откроется в Telegram.
const _allowedParameters = {'server', 'port', 'secret'};

final _port = RegExp(r'^\d{1,5}$');
final _hexSecret = RegExp(r'^(?:dd|ee)[0-9a-fA-F]+$');
final _hostname = RegExp(
  r'^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$',
);

class _Checked {
  const _Checked(this.link, this.error);
  final MtprotoProxyLink? link;
  final String? error;

  static _Checked ok(MtprotoProxyLink link) => _Checked(link, null);
  static _Checked fail(String error) => _Checked(null, error);
}

_Checked _check(String raw) {
  final text = raw.trim();
  if (text.isEmpty) return _Checked.fail('Ссылка не заполнена');

  final uri = Uri.tryParse(text);
  if (uri == null || uri.userInfo.isNotEmpty || uri.hasFragment) {
    return _Checked.fail('Не удалось разобрать ссылку');
  }
  final scheme = uri.scheme.toLowerCase();
  final host = uri.host.toLowerCase();
  final isTelegram = scheme == 'tg' && host == 'proxy' && uri.path.isEmpty;
  final isWeb =
      scheme == 'https' &&
      (host == 't.me' || host == 'telegram.me') &&
      uri.path == '/proxy';
  if (!isTelegram && !isWeb) {
    return _Checked.fail(
      'Ссылка должна начинаться с tg://proxy?… или https://t.me/proxy?…',
    );
  }

  // Повтор параметра означает неоднозначность — такую ссылку не сохраняем.
  // Сравниваем число значений, а не число ключей: queryParameters схлопывает
  // дубликаты в один ключ, поэтому по длине карт дубль не виден.
  final values = uri.queryParametersAll;
  final totalValues = values.values.fold<int>(0, (sum, v) => sum + v.length);
  if (totalValues != values.length) {
    return _Checked.fail('В ссылке повторяется параметр');
  }
  for (final key in uri.queryParameters.keys) {
    if (!_allowedParameters.contains(key)) {
      return _Checked.fail('Лишний параметр в ссылке: $key');
    }
  }

  final server = uri.queryParameters['server']?.trim() ?? '';
  if (server.isEmpty) return _Checked.fail('В ссылке нет адреса сервера');
  if (!_validServer(server)) {
    return _Checked.fail('Адрес сервера должен быть IP или доменом');
  }

  final portText = uri.queryParameters['port']?.trim() ?? '';
  if (portText.isEmpty) return _Checked.fail('В ссылке нет порта');
  if (!_port.hasMatch(portText)) {
    return _Checked.fail('Порт должен быть числом от 1 до 65535');
  }
  final port = int.parse(portText);
  if (port < 1 || port > 65535) {
    return _Checked.fail('Порт должен быть числом от 1 до 65535');
  }

  final secret = uri.queryParameters['secret']?.trim() ?? '';
  if (secret.isEmpty) return _Checked.fail('В ссылке нет секрета');
  if (!_validSecret(secret)) {
    return _Checked.fail(
      'Секрет должен быть hex-строкой (ee… или dd…) либо base64 тех же байт',
    );
  }

  return _Checked.ok(
    MtprotoProxyLink(server: server, port: port, secret: secret),
  );
}

/// Адрес прокси: литеральный IPv4/IPv6 или домен. Петлевые и «нулевые»
/// адреса отклоняем — такой прокси заведомо не работает.
bool _validServer(String value) {
  final text = value.startsWith('[') && value.endsWith(']')
      ? value.substring(1, value.length - 1)
      : value;
  final address = InternetAddress.tryParse(text);
  if (address != null) {
    return !address.isLoopback && text != '0.0.0.0' && text != '::';
  }
  return _hostname.hasMatch(value);
}

/// Секрет MTProto: hex с префиксом `dd`/`ee` или base64 тех же байт.
///
/// Telegram выдаёт hex длиной 34 символа для `dd…` и длиннее для `ee…`
/// (в FakeTLS-секрет зашит домен маскировки), поэтому проверяем только
/// префикс и чётную длину — конкретную длину задаёт сервер прокси.
bool _validSecret(String value) {
  if (_hexSecret.hasMatch(value)) {
    return value.length.isEven && value.length >= 34;
  }
  try {
    final bytes = base64Url.decode(base64Url.normalize(value));
    if (bytes.length < 17) return false;
    return bytes.first == 0xdd || bytes.first == 0xee;
  } on FormatException {
    return false;
  }
}
