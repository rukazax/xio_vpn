# XIO: доменное имя сервера наравне с IPv4/IPv6 в приложении, 30.10.2026

Задача владельца TG202: подключение к серверу по доменному имени должно работать так же, как по IPv4/IPv6. Проверены и исправлены только app-пути (`app/lib/**`, `app/test/**`) и отчётность. Server/native/remote, сеть, устройства, секреты и DNS не изменялись.

## Что было исправлено

- `app/lib/server_address.dart`
  - Единый валидатор `normalizeServerHost`: домен, IPv4, IPv6, IPv6 в скобках; скобки снимаются только для socket/DNS, в endpoint возвращаются.
  - `ServerEndpoint.parse`: строгий разбор `host:port`; отдельный порт, скобки только для IPv6; отказ от схем, `host:port` в поле хоста, userinfo, пути, query, fragment, лишних `:`.
  - `resolveServerHost`: платформенный DNS, отдельные запросы A и AAAA, дедупликация, **перемежающийся порядок IPv4, IPv6, следующий IPv4…** до любого бюджета попыток; IP-литералы не ходят в DNS. Без внешних библиотек и без подстановки чужого адреса вместо имени.
- `app/lib/core.dart`
  - `SshTarget.validate` использует общий валидатор, а не прежний разрешающий regex.
  - `VpsService.open` нормализует фактический socket-host, разрешает A/AAAA и пробует кандидатов в **перемежающемся** порядке. DNS-фаза — до 8 с (A и AAAA параллельно); 12 с — отдельный бюджет сокет-попыток уже после DNS, по 5 с на кандидата. Проверка host key остаётся привязанной к исходному `SshTarget` (домену); при несовпадении pin соединение останавливается до аутентификации, без перебора «алиасов», без повторной попытки другого адреса и без отправки пароля.
  - `SshHostKeyStore` канонизирует host при формировании ключа known-hosts, поэтому `[IPv6]` и raw IPv6 не создают разные записи.
  - `WireGuardProfile`, `ClientImport` и `NetworkChecks` используют общий endpoint-разбор; диагностика показывает A и AAAA и проверяет оба семейства.
- `app/lib/managed_models.dart`
  - `ManagedServer.host` (SSH-транспорт) и `publicHost` (VPN-адрес) валидируются и нормализуются отдельно.
  - Пустой/отсутствующий `publicHost` наследует `host` для старых профилей; экспорт/импорт сохраняет оба поля.
- `app/lib/managed_service.dart`
  - Установка отправляет в `init` именно VPN-домен (`publicHost`), а SSH-прокси и его порт остаются только транспортом управления. Пустой `publicHost` трактуется как адрес SSH.
- `app/lib/subclients.dart`
  - `provisioningBundle` больше не дублирует loose-regex и ручную сборку endpoint: домен/IP проходят общий валидатор, AWG/RIVET получают `serverEndpoint`.
- `app/lib/rivet_profile.dart`, `app/lib/extended_profile.dart`
  - RIVET endpoint разбирается общим `ServerEndpoint`, канонизируется при сохранении; `serverName` проверяется отдельно и не подменяется VPN-хостом.
  - Extended (Xray/Cloak) address/SNI проверяются общим валидатором; scheme/host:port/injection отклоняются; SNI остаётся самостоятельной identity.
- `app/lib/workspace_ui.dart`
  - В поле SSH явно указано: IPv4, IPv6 или домен; SSH-порт — отдельное поле; добавлен пример `vpn.example`; отключены autocorrect/подсказки.
  - Поле VPN-адреса по-прежнему отдельно поясняет: IPv4, IPv6 или домен самого VPS, не SSH-прокси.

## Тесты

Добавлен `app/test/domain_host_test.dart` (749 строк): реальные формы `fr-host.fr` и `VPS-721137.ssh.vps1euro.fr:9046`, независимость management-прокси и VPN-хоста, A/AAAA-резолвинг и перемежающийся порядок (3×A + 1×AAAA и 3×AAAA + 1×A), порядок сокет-попыток, «нет второго адреса после установленного сокета», смена pin для домена, AWG/RIVET/extended, subclient provisioning, UI-подсказки, отказ от схем/портов/инъекций.

Команды и результат:

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\app
C:\dev\flutter\bin\flutter.bat analyze --no-pub
# No issues found! (ran in 4.3s)

C:\dev\flutter\bin\flutter.bat test test\domain_host_test.dart test\server_address_test.dart test\rivet_profile_test.dart test\extended_profile_test.dart test\security_test.dart --no-pub
# All tests passed! (+65)
```

Дополнительно прогнан расширенный набор (domain_host, server_address, security, rivet_profile, extended_profile, managed_models, ssh_trust, protocol_compatibility, client_import): 87 тестов прошли. `account_access_test.dart` (6 тестов TLS/редиректов) прошёл после добавления в PATH `C:\Program Files\Git\usr\bin`; в обычном PATH этого окружения `openssl` отсутствует. Локальная проверка raw IPv6 socket: `Socket.connect('::1', ...)` — `raw-ipv6-socket: ok ::1`.

Новые детерминированные регрессии (все в `app/test/domain_host_test.dart`):

- `three A answers never starve the single AAAA answer` — порядок `A1, AAAA1, A2, A3`, AAAA на индексе 1;
- `three AAAA answers never starve the single A answer` — порядок `A1, AAAA1, AAAA2, AAAA3`;
- `socket attempts try the AAAA answer before extra A records` — фактический порядок вызовов `VpsService`-коннектора при 3×A + 1×AAAA;
- `an established socket is never replaced by another address` — после установленного сокета ровно одна попытка, даже если сессия падает (путь pin mismatch);
- `a changed key for the domain aborts before authentication` — смена ключа для `[fr-host.fr]:22` отклоняется и не перезаписывает сохранённый pin;
- IP-литералы по-прежнему не ходят в DNS (`DNS candidate resolution asks A and AAAA separately`).

## Границы и известные ограничения

- Живой VPS/SSH, VPN data-plane, DNS/SNI на реальном провайдере и Android-устройство не запускались: это зона parent/server/native/remote; ADB не использовался.
- Кандидаты DNS разрешаются параллельно (A и AAAA, до 8 с каждый), затем пробуются последовательно в перемежающемся порядке: IPv4, IPv6, следующий IPv4…; при нескольких кандидатах 5 с на попытку, 12 с — бюджет только сокет-попыток после DNS. Параллельного happy-eyeballs нет.
- `NetworkChecks` делает 3 TCP-попытки по кругу кандидатов и сообщает фактически затронутые семейства; это диагностика, не доказательство отсутствия утечек.
- Отключение/истечение профиля не менялись, поэтому отдельные regressions для них не добавлялись.
- В рабочем дереве параллельно есть чужие изменения `protocol/rivet/**` и `server/managed/**`; они не трогались. Наши backups и хэши: `work/domain-host-20261030/app/`.

## Стабильная stage для live SSH

Готовый снимок без `build/`, `android/`, `ios/`, `linux/`, `windows/`:

`C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\work\domain-host-20261030\app\stage\app-final`

Проверено в stage:

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\work\domain-host-20261030\app\stage\app-final
C:\dev\flutter\bin\flutter.bat test test\ssh_dualstack_live_test.dart --no-pub
# All tests skipped. (2) — live-тест ждёт XIO_LIVE_SSH=1 и эфемерные env
C:\dev\flutter\bin\flutter.bat test test\domain_host_test.dart --no-pub
# All tests passed! (+20)
```

Изменённые тесты: только `app/test/domain_host_test.dart` (новый файл); `app/test/server_address_test.dart` и `app/test/ssh_dualstack_live_test.dart` не менялись. Для live-проверки parent использует stage выше и подаёт `XIO_LIVE_SSH=1`, `XIO_LIVE_SSH_HOST`, `XIO_LIVE_SSH_PASSWORD`, `XIO_LIVE_SSH_PIN`, `XIO_LIVE_SSH_PORT` в процессе; секреты не сохраняются.

## Файлы

Изменены:
`app/lib/server_address.dart`, `app/lib/core.dart`, `app/lib/managed_models.dart`, `app/lib/managed_service.dart`, `app/lib/subclients.dart`, `app/lib/rivet_profile.dart`, `app/lib/extended_profile.dart`, `app/lib/workspace_ui.dart`.

Добавлены:
`app/test/domain_host_test.dart`, `docs/verification/domain-host-app-20261030.ru.md`, `work/domain-host-20261030/app/**`.

Никаких commit/revert/build APK/release не выполнялось.
