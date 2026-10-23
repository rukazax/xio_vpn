import 'dart:io';

import 'l10n.dart';

export 'build_identity.dart';

const clientDisclosureRu = '''XIO Client использует Android VpnService для подключения к выбранному вами существующему VPN-серверу. Между устройством и сервером трафик шифруется. Владелец сервера может видеть ваш IP, назначения и сетевые метаданные; содержимое HTTPS дополнительно защищено HTTPS.

Профили и запись ознакомления хранятся на устройстве. Секреты профилей защищены Android Keystore. Приложение не устанавливает и не администрирует серверы, не принимает SSH-доступ, не раздаёт VPN и не содержит рекламного или аналитического SDK. При отдельно выданном доступе аккаунта HTTPS API выбранного сервера проверяет серверный лимит, создаёт и отзывает только его субклиентов. Для этого хранится ограниченный API-токен с закреплённым сертификатом; SSH/root/admin-ключи не передаются. Профиль субклиента содержит только его VPN-ключи и не наследует API-доступ родителя. Состояние незавершённого создания сохраняется локально в защищённом хранилище, чтобы не повторять операцию с новым ID.

Встроенного каталога серверов нет: импортируйте клиентский профиль, полученный от вашего администратора. Проверка соединения обращается к выбранному HTTPS-сайту (по умолчанию youtube.com), который видит адрес выхода. DNS использует настройки профиля.

Раздельное туннелирование позволяет направлять через VPN только выбранные приложения либо исключать их; отдельно доступны правила IP/CIDR. Исключённый трафик идёт напрямую. Доменные правила не поддерживаются. Системная блокировка трафика без VPN может запретить обход. При переключении серверов старый туннель сначала отключается: в этот промежуток защита VPN отсутствует, если не включена системная блокировка. Приложение не обещает обход любых блокировок или анонимность.

Перед первым подключением Android отдельно запросит разрешение VPN. Если вы не согласны, закройте приложение без подтверждения.''';

const clientDisclosureEn = '''XIO Client privacy policy
Revision: 23 October 2026. Developer: Konstantin Eryomin, er-ka@mail.ru.

The client connects to existing servers using imported client profiles. Profiles and settings remain on the device; profile secrets use encrypted Android Keystore-backed storage excluded from backups. This does not guarantee protection on a compromised device. Acknowledgements record the document revision, device UTC timestamp, language and displayed text SHA-256; they are not sent to the developer.

VpnService encrypts selected traffic to the chosen endpoint. Its operator may observe the connecting IP, destinations and metadata; HTTPS separately protects content. DNS follows the profile. Connectivity checks contact the chosen HTTPS website (youtube.com by default), which sees the exit IP. With split tunnelling, the probe may use a direct route and does not establish protection of other applications. Excluded applications or networks use direct networking unless Android lockdown blocks that traffic.

An explicitly issued account API token can check quota, create and revoke only its own subclients through the selected server HTTPS API with a pinned certificate. The token and unfinished operation are stored encrypted locally. Child exports contain only that child’s VPN keys; parent capability and SSH/root/admin keys are excluded. Subclient records also remain on the server.

This build has no VPS deployment or administration, SSH, VPN sharing, endpoint geolocation, background release checks, advertising or analytics SDK, or automatic crash reporting. A system document picker imports files without broad storage access. Launchable application names are read locally for routing selection and are not sent to the developer. Android FLAG_SECURE blocks application screenshots.

Data remains until profiles are removed, application data is cleared or the application is uninstalled. Local deletion does not remove a server or revoke its credentials. The server operator controls access and server-side processing. Support contact is voluntary; never send passwords or private keys. Android separately requests VPN permission; a new connection requires consent.
''';
String get clientDisclosure {
  if (Platform.isAndroid) {
    return AppLanguages.effective == 'ru'
        ? clientDisclosureRu
        : clientDisclosureEn;
  }
  return AppLanguages.effective == 'ru'
      ? 'XIO Client подключается к существующему серверу и не принимает SSH/root/admin-ключи сервера. Профили остаются на устройстве: iOS использует Keychain, Windows — DPAPI, Ubuntu — AES-GCM с локальным ключом и правами файлов. Взломанный аккаунт или ОС могут нарушить эту защиту. Оператор сервера видит IP, назначения и метаданные; HTTPS отдельно защищает содержимое. Проверка выбранного HTTPS-сайта раскрывает ему адрес выхода. Ограниченный API аккаунта создаёт и отзывает только своих субклиентов в серверной квоте.\n\nНативные возможности пока различаются: iOS — RIVET/H3 и S1, desktop — также AWG и Xray. Полная совместимость пяти протоколов и общие раздельные маршруты пока не реализованы. Для этих кандидатов не заявлены универсальные kill-switch, запрет снимков экрана или непрерывная работа в фоне. Подробности указаны в политике конфиденциальности.'
      : 'XIO Client connects to an existing server and does not accept server SSH/root/admin keys. Profiles remain on this device: iOS uses Keychain, Windows uses DPAPI, Ubuntu uses AES-GCM with a local key and file permissions. A compromised account or OS can defeat that protection. The server operator observes addresses, destinations and metadata; HTTPS separately protects content. The selected HTTPS check site sees the exit IP. A restricted account API can create/revoke only its own subclients under the server quota.\n\nNative features still differ: iOS declares RIVET/H3 and S1; desktops also declare AWG and Xray. Full five-protocol parity and common split routing are not implemented yet. Universal kill-switch, screenshot blocking or continuous background persistence is not claimed for these candidates. See the privacy policy for details.';
}
