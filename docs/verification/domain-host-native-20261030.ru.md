# XIO VPN — доменное имя сервера в native- и managed-слое

30.10.2026

## Итог

Запрос владельца (TG202): доменное имя сервера должно быть первоклассным адресом
наряду с IPv4/IPv6, а не только числовым endpoint. В срезе проверены и закрыты
разрывы в `protocol/rivet/**` и `server/managed/**`, которые мешали такому
профилю доходить до платформенного DNS без потери TLS/SNI-идентичности.

Это **не общий E2E PASS VPN**. Живой DNS, удалённый TLS, helper/TUN, маршруты,
firewall, Android/iOS runtime и удалённая установка сервера не запускались.

## Границы работ

- Канонический репозиторий: `C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit`.
- Исходный HEAD: `689ac18e9978bea20205763b85263181e0ef264e`; worktree уже был dirty,
  старые изменения сохранены. Перед правками сделаны копии и SHA-256 в
  `work/domain-host-20261030/native/`.
- Мой write scope: `protocol/rivet/**`, `server/managed/**` (только доменная
  обработка и тесты), этот документ и `work/domain-host-20261030/native/`.
- Мной `app/**` не изменялся. Dart/UI и live SSH-тест остаются за sibling/app-владельцем.
- Не запускались: VPN helper, TUN, маршруты, firewall, удалённые серверы/SSH,
  Android-устройства, публикация, git commit/push. Remote live-проверка родителя
  в этот срез не входит; её адреса в код и тесты не зашиты.

## Что уже работало и не переписывалось

- `ClientConfig.Endpoint` уже принимал `host:port`, а TLS identity хранится
  отдельно в `ServerName`; outer TLS использует `ServerName`, а не числовой
  endpoint.
- `physical.Addresses`, `physical.Resolve` и `physical.Dial` уже были
  dual-stack, bounded, только с numeric-адресами и без fallback на системный DNS.
- Desktop `EndpointCandidates` и `prepareEndpoints` уже резервировали bypass для
  всех A/AAAA-кандидатов; mobile `dialPhysical` уже перебирал кандидаты; Apple
  resolver уже отдавал один numeric IP за callback и ротировал семейство.
- `server/managed/rivet-setup.py:public_address` в dirty worktree уже формировал
  endpoint для домена и скобки для IPv6. Эти полезные части сохранены.
- `rivet init` по-прежнему экспортирует `port=8443`, pin/gatewayId и список
  протоколов; `setup.py install` добавляет валидированные `endpoint` и
  `serverName` через `public_address`. Отдельного доменного поля в `init` нет и
  не требуется: контракт остаётся `host` + `serverName`.

## Найденные разрывы и внесённые правки

1. **Core validation был слишком слабым.** `ClientConfig.Validate` проверял лишь
   непустые host/port. Проходили `[fr-host.fr]:8443`, `bad host:8443`,
   `fr-host..fr`, `fr_host.fr`, порт `https`, некорректный `ServerName`.
   Добавлены `physical.ValidHost` и `physical.ParseEndpoint`; `Validate`
   использует их для endpoint и `ServerName`. Скобки разрешены только для
   IPv6-литерала, порт обязан быть числовым 1..65535, длина ограничена 253
   байтами (как в app-boundary), ASCII-метки и trailing dot проверяются.
2. **Системный DNS в `Dial`.** Для h3 профиль с доменом мог дойти до
   `net.ResolveUDPAddr`, для s1 — до `net.Dialer` с системным DNS. Теперь
   `DialWithTimeout` требует уже разрешённый numeric endpoint и возвращает
   `rivet: endpoint must be resolved before dialing`. Платформенный слой
   (`physical.Resolve`) остаётся единственным DNS-путём.
3. **Desktop AWG и `prepareEndpoints`.** AWG `Endpoint` принимал `host:port` без
   проверки хоста; `prepareEndpoints` игнорировал ошибку `SplitHostPort`.
   Оба места переведены на `physical.ParseEndpoint`, поэтому malformed-хост и
   скобочный домен отсекаются до DNS/bypass.
4. **Xray.** `endpoint()` отсекал только NUL/переводы строки и `/`; теперь
   используется `physical.ValidHost`. Домены и Punycode принимаются, скобочный
   домен, пробелы, подчёркивания и `host:port` в поле address — нет.
5. **Mobile/Apple parsing.** `mobile.resolve`, `resolveTimed`, `dialPhysical` и
   `apple.resolve` теперь используют общий `ParseEndpoint`. Apple больше не
   игнорирует ошибку разбора и проверяет единственный numeric-ответ через
   `physical.Addresses` (контракт Apple ABI: один IP за callback). `ServerName`
   сохраняется без изменений.
6. **Серверный host acceptance.** `public_address` принимал строки без проверки:
   пробелы, `fr-host.fr:8443`, `[fr-host.fr]`, `fr-host..fr`, числовой
   pseudo-IP. Добавлен `valid_name`; он же проверяется в `install` до побочных
   эффектов. `admin.init` получил `valid_host` и проверяет хост до сохранения
   deployment. Домен, Punycode, trailing dot и IPv4/IPv6 принимаются; Unicode
   IDN, скобки, zone id и port-in-host отклоняются.
7. **TLS identity.** `GenerateOuter` проверяет имя сертификата и не создаёт
   сертификат для malformed `ServerName`. Ветка SAN уже была корректной: для
   `net.ParseIP(name)` заполняется `IPAddresses`, иначе `DNSNames`. Это теперь
   зафиксировано тестами: IPv4/IPv6 identity проверяются через
   `VerifyHostname`, DNS identity — через цепочку и SNI. `outerTLSConfig`
   вынесен в отдельную функцию, чтобы SNI/проверка всегда использовали
   `ServerName`, а не выбранный numeric candidate.
8. **Явный diagnostic-путь для CLI/probe.** Низкоуровневый `DialWithTimeout`
   остаётся numeric-only: профиль с доменом отклоняется до сокета
   (`rivet: endpoint must be resolved before dialing`), поэтому protected VPN
   path не может уйти в системный DNS. Высокоуровневый `Dial` с protector —
   тот же защищённый контракт; `Dial` без protector — явный diagnostic-путь.
   Для standalone `rivet probe` добавлен `rivet.DialDiagnostic`: bounded
   OS-resolver (`net.DefaultResolver`), затем последовательный перебор
   numeric-кандидатов в одном общем deadline. Порядок, дедупликация и
   interleaving семей переиспользуют `physical.Addresses`; `ServerName`, pin и
   остальные поля профиля копируются без изменений. `ResolveEndpointCandidates`
   доступен отдельно для диагностики. Это не меняет защищённый контракт:
   mobile/Apple/desktop/Xray по-прежнему получают адреса только от
   платформенного resolver.

Новых DNS-библиотек и собственного DNS-резолвера нет. Используются
`net.SplitHostPort`, `net.JoinHostPort`, `net.ParseIP`, `net.DefaultResolver`
(только явный diagnostic API) и платформенный resolver.

## Изменённые и новые файлы

Изменены:

- `protocol/rivet/internal/physical/network.go`
- `protocol/rivet/internal/rivet/config.go`
- `protocol/rivet/internal/rivet/client.go`
- `protocol/rivet/internal/desktop/profile.go`
- `protocol/rivet/internal/desktop/runtime.go`
- `protocol/rivet/internal/xrayclient/client.go`
- `protocol/rivet/mobile/mobile.go`
- `protocol/rivet/apple/apple.go`
- `server/managed/rivet-setup.py`
- `server/managed/admin.py`
- `server/managed/test_rivet_public.py`
- `server/managed/test_update_ipv6.py`
- `protocol/rivet/cmd/rivet/main.go`

Новый код:

- `protocol/rivet/internal/rivet/endpoint.go` (`ResolveEndpointCandidates`,
  `DialDiagnostic`)

Новые тесты:

- `protocol/rivet/internal/physical/hostname_test.go`
- `protocol/rivet/internal/rivet/hostname_test.go`
- `protocol/rivet/internal/rivet/endpoint_test.go`
- `protocol/rivet/internal/desktop/hostname_test.go`
- `protocol/rivet/internal/xrayclient/hostname_test.go`
- `protocol/rivet/mobile/hostname_test.go`
- `protocol/rivet/apple/hostname_test.go`
- `server/managed/test_host_validation.py`

Документ: `docs/verification/domain-host-native-20261030.ru.md`.

## Детерминированные regression-тесты

Основной домен — `fr-host.fr`; дополнительно обычные `vpn.example.com`,
`localhost`, trailing-dot `fr-host.fr.`, Punycode `xn--bcher-kva.example`
(включая регистр), IPv4/IPv6-литералы и mapped IPv6.

- Host boundary: валидные домены/адреса; пустая строка, пробелы, `host:port`,
  `[fr-host.fr]`, `[2001:db8::42]`, двойные точки, ведущий/хвостовой дефис,
  подчёркивание, числовой pseudo-IP, zone id, метка 64 байта, имя 254 байта.
- Endpoint parsing: домен и IPv6 в скобках, отказ для `[domain]`, `[IPv4]`,
  нечислового/нулевого/слишком большого порта; сохранение точного host для DNS.
- DNS-кандидаты: A-only, AAAA-only, dual, multi A/AAAA с чередованием семей,
  Punycode и trailing dot. Проверяется, что `EndpointCandidates` содержит все
  numeric-адреса, bypass вызван для каждого, а `ServerName` не меняется.
- Diagnostic DNS: `ResolveEndpointCandidates`/`DialDiagnostic` на A-only,
  AAAA-only, dual и multi-ответах; проверяются порядок, дедупликация, порт,
  сохранение `ServerName`/pin, отказ при malformed endpoint до lookup,
  `context.Canceled`, deadline зависшего lookup, ошибка и пустой ответ DNS,
  fallback на следующий кандидат и остановка после отмены. Отдельные тесты
  доказывают, что protected `DialWithTimeout` с доменом не вызывает protector
  и падает до сокета, а diagnostic-вызов не отменяет context, который остаётся
  у возвращённой сессии (регрессия была поймана integration-тестом).
- IP SAN: `GenerateOuter` для IPv4 и IPv6 заполняет `IPAddresses` (не
  `DNSNames`), а `VerifyHostname` проходит для литерала; для домена — `DNSNames`
  и проверка цепочки. Это фиксирует уже существующую поддержку IP identity.
- AWG: доменный `Endpoint = fr-host.fr:51820` парсится, затем разрешается в
  numeric candidates; malformed-варианты отклоняются.
- TLS/SNI: локальный `net.Pipe`, сертификат из `GenerateOuter` для домена,
  trailing-dot, Punycode и IP-литералов. Проверяется успешная проверка цепочки
  и наблюдаемый SNI; Go нормализует trailing dot в SNI (`fr-host.fr`), при этом
  сертификат с точкой проверяется по настроенному identity.
- Mobile/Apple: A-only, AAAA-only, dual, trailing dot, Punycode, literal bypass,
  пустой ответ, malformed endpoint; Apple отдельно проверяет single-IP ABI и
  отказ от comma-list.
- Server: `public_address('fr-host.fr')`, trailing dot, Punycode, IPv4/IPv6,
  mapped IPv6; malformed-список; `valid_name`/`valid_host` length-boundary 253.
- Update migration: доменные `fr-host.fr`, `fr-host.fr.`, Punycode сохраняют
  `public.json` байт-в-байт и не перевыпускают ключи.

## Проверки, exit и количества

Все команды — только Windows-хост, без запуска helper/TUN/маршрутов/firewall.

```text
cd protocol/rivet
gofmt -l <17 изменённых Go-файлов>        -> пусто, exit 0
git diff --check -- <изменённые tracked-файлы> -> exit 0
  (только pre-existing LF/CRLF warnings)
go vet ./internal/physical ./internal/rivet ./internal/desktop \
       ./internal/xrayclient ./mobile ./apple   -> exit 0
go test -count=1 ./internal/physical ./internal/rivet ./internal/desktop \
       ./internal/xrayclient ./mobile ./apple   -> exit 0
  126 PASS, 0 FAIL, 4 SKIP (verbose)
go test -count=1 -run 'TestResolveEndpointCandidates|TestProtectedDialRejectsHostname|TestDialDiagnostic|TestOuterCertificateIdentitySANs' ./internal/rivet
                                              -> exit 0 (8 диагностических тестов)
go build -o %TEMP%\xio-desktop-domain-host.exe ./cmd/xio-desktop
                                              -> exit 0 (только компиляция)
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'; go build ./...
                                              -> exit 0 (cross-compile, не запуск)
go test -count=1 ./...                        -> exit 1:
  cmd/rivet: undefined rivet.OpenTUN, unix.Flock, unix.LOCK_EX
  (pre-existing Windows/Linux build-tag ограничение; остальные пакеты ok)
```

`go test -count=1 ./...` — единственный ненулевой exit. Он относится к
`cmd/rivet`, который использует Linux-only OpenTUN/fcntl; на Windows этот пакет
не собирается и pre-existing тест-путь не менялся. Правка probe в `cmd/rivet`
проверена Linux cross-compile `go build ./...` (exit 0). Все пакеты, куда
входили правки, проходят.

```text
cd server/managed
python -m py_compile rivet-setup.py admin.py test_rivet_public.py \
        test_host_validation.py test_update_ipv6.py   -> exit 0
python -m unittest -v test_rivet_public test_host_validation test_update_ipv6
                                                       -> 26 tests, OK, exit 0
python -m unittest -v test_admin                       -> 9 tests, OK, exit 0
```

Для Windows-запуска `test_update_ipv6`/`test_admin` во временном `PYTHONPATH`
использовался stub модуля `fcntl` (на Windows его нет). Linux-команды не
выполнялись; `update`-тесты работают на mock/fixture. Без stub эти два файла
не импортируются на Windows — это ограничение стенда, не бизнес-логики.

Полные логи: `work/domain-host-20261030/native/go-test-verbose.log`,
`go-test-all.log`, `python-test.log`, `python-admin-test.log`.

## Остаточные ограничения

- Нет live-проверки A/AAAA, DNS fallback, TLS/SNI к реальному серверу, TUN,
  helper, маршрутов, firewall, Android/iOS device runtime и установки на VPS.
- 4 SKIP в Go — pre-existing: `TestBothCarriersIPv6EndpointAndPayload`
  (нет IPv6 loopback), `TestVPSProfiles`, `TestVPSCloakAuth`, `TestVPSPacketFlow`
  (нужны private VPS fixtures).
- `rivet probe` по домену теперь работает через явный bounded OS DNS и перебор
  numeric-кандидатов (`DialDiagnostic`), сохраняя `ServerName`/pin. Protected
  VPN path по-прежнему не делает системный DNS: он получает numeric-кандидаты
  от платформенного resolver. Live-probe к реальному серверу не запускался.
- `GenerateOuter` для IP identity уже использовал `IPAddresses`; это
  pre-existing поведение, теперь покрытое тестами, без ослабления проверки.
  Для IPv4-mapped IPv6 (`::ffff:…`) отдельная SAN-проверка не заявляется.
- `server/managed/update.py:rivet_metadata` оставлен с прежним мягким regex для
  исторических deployment-метаданных; новые install/init проходят строгую
  проверку. Старые имена не переписываются.
- Ограничение 253 байта согласовано с app-boundary (`normalizeServerHost`).
  Trailing dot сохраняется в `serverName` и endpoint; Go отправляет SNI без
  trailing dot, но проверяет сертификат по настроенному identity.
- Punycode принимается только в ASCII-форме `xn--…`; Unicode IDN отклоняется
  так же, как в app. Link-local IPv6 и zone id отклоняются общим physical
  контрактом.
- `app/**`: sibling/app-владелец уже правит этот слой в текущем worktree:
  `SshTarget.validate` вызывает `normalizeServerHost`, `VpsService.open`
  нормализует socket-host, `SshHostKeyStore` нормализует host для ключа, а
  host-key pin проверяется до credentials. Я эти файлы не трогал и live SSH не
  запускал; live-тест сохранён. Остаётся невыполненной только удалённая
  SSH-приёмка; нельзя ослаблять pin через DNS-алиас или подмену identity.

## Передача

`app/lib`, `app/test`, UI и live SSH — sibling/app-владелец. В текущем
worktree sibling уже нормализует `SshTarget`, socket-host и ключ host-key store;
это не мои изменения и не проверялось live. `app/test/ssh_dualstack_live_test.dart`
сохранён. Серверный контракт
для него: `serverName` — bare host (IPv6 без скобок), endpoint — `host:8443`
или `[IPv6]:8443`, trailing dot сохраняется, порт в host запрещён. Android не
использовался; при необходимости Android действовать только через
существующий эксклюзивный registry.
