# XIO changes / Изменения
## Не выпущено — отказ от прежнего имени / Unreleased — retiring the former name

RU: приём ссылок прежней схемы удалён полностью: импорт понимает только `xio://` и `xio-server://`, всё остальное отклоняется как неизвестная схема. Данные прежних установок не читаются, послабления для прежних путей убраны из серверного юнита, а подпись APK не изменилась — обновление проверяется по SHA-256 сертификата (`e4e81b12…c9671`), а не по имени в сертификате. Предупреждение пользователям: [docs/ru/updates.md](docs/ru/updates.md).

EN: acceptance of the former link scheme is gone: import understands only `xio://` and `xio-server://`, everything else is rejected as an unknown scheme. Data of former installations is not read, the former paths are no longer whitelisted by the server unit, and the APK signature is unchanged — updates are verified by the certificate SHA-256 (`e4e81b12…c9671`), not by the name inside the certificate. User-facing note: [docs/en/updates.md](docs/en/updates.md).

## 0.24.2 — 2026-11-04, слияние rc13 с main: каскад, −7 МиБ APK, батарея

RU: 0.24.1 исправляет серверный пакет 0.24.0: `bootstrap.sh` выносил `readiness.py` и `xio-ready.service`, но упаковщик их не включал, поэтому любая установка на чистом хосте завершалась кодом 1 на последнем шаге. Оба файла теперь входят в архив, `RECIPE` поднят до 27, а `update.py` принимает 25 и 26 как источники миграции — иначе установленные хосты не смогли бы обновиться. Текст архива (`*.py`, `*.json`, `*.sh`) пакуется с переводами строк LF и хешируется после нормализации, поэтому сборка на Windows и на Linux даёт одинаковый архив; из-за этого меняется байтовый хеш `mesh-pins.json` (`cf2bd08f…` → `ea7a3b5d…`) при том же содержимом JSON — ошибки в нём нет. `stats()` больше не падает с `KeyError` на хосте `restrictedNetwork`: ключи `wireguard` без работающего юнита дают нулевые счётчики, а не обрывают всю выборку и месячный учёт трафика. У пакета `probe-physical` появился build-тег `windows` — без него `go test -race ./...` падал на Linux и серверный архив нельзя было собрать ни на одной Linux-машине. Версия приложения 0.24.1+5018. Добавлен каталог «белых» SNI: серверный пакет приносит генератор, pin источника и недельный таймер, а администратор читает пригодные имена действием `catalog`; каталог не маршрутизирует по домену и не применяет маску сам. [Подробности](docs/whitelist/0.24.1.ru.md). Сборка проверена на Debian 13 стенде: `build-rivet` rc=0, `package-server` даёт 27 членов, повторный прогон даёт тот же sha256, CRLF-дерево даёт тот же архив, replay установочной секции `bootstrap.sh` — 15 целей, missing=0, rc=0. Стенд собран до подъёма `RECIPE` до 27: после смены рецепта архив нужно пересобрать и сверить `recipeVersion` 27 в манифесте. Чистая Ubuntu 22.04 и публикация — на приёмке.

EN: 0.24.1 fixes the 0.24.0 server package: `bootstrap.sh` moved `readiness.py` and `xio-ready.service` out of the tarball, but the packager never shipped them, so every install on a clean host ended with exit code 1 on the last step. Both files are members again, `RECIPE` is 27 and `update.py` accepts 25 and 26 as migration sources, otherwise installed hosts could not upgrade. Archive text members (`*.py`, `*.json`, `*.sh`) are packed with LF endings and hashed after normalisation, so a Windows and a Linux build produce the same archive; as a result the byte hash of `mesh-pins.json` changes (`cf2bd08f…` → `ea7a3b5d…`) while the JSON content is identical — this is not an error. `stats()` no longer raises `KeyError` on a `restrictedNetwork` host: `wireguard` keys without a running unit yield zero counters instead of aborting the whole sample and the monthly traffic accounting. The `probe-physical` package now has a `windows` build tag; without it `go test -race ./...` failed on Linux and the server archive could not be built on any Linux machine. App version 0.24.1+5018. A white-SNI catalog is included: the server package ships the builder, the source pin and a weekly timer, and an administrator reads the eligible names through the `catalog` action; the catalog does not route by domain and never applies a mask on its own. [Details](docs/whitelist/0.24.1.ru.md). Build verified on a Debian 13 stand: `build-rivet` rc=0, `package-server` yields 27 members, a second run gives the same sha256, a CRLF tree gives the same archive, replay of the `bootstrap.sh` install section — 15 targets, missing=0, rc=0. The stand build predates the `RECIPE` bump to 27: after the recipe change the archive must be rebuilt and its manifest checked for `recipeVersion` 27. Clean Ubuntu 22.04 and publication are pending acceptance.

## 0.24.0 — 2026-10-31, исправление серверной установки

RU: 0.24.0 исправляет серверную установку. Пакет 0.23.1 не ставился: правило `nat POSTROUTING` собиралось с входным интерфейсом, и `iptables` отвечал `Can't use -i with POSTROUTING`; на хосте только с IPv6 дополнительно падали `status` и таймер статистики из-за `wg show xio0` при отсутствующем интерфейсе. Теперь область `-i` остаётся только в `FORWARD`, а `counters()` пропускает несуществующие интерфейсы. Проверено живой установкой на Debian 13 (LXC, `fr-host.fr`): bootstrap 0, `init` ok, `recipeVersion` 25, сервис active. Android: Full 0.24.0 ставится поверх 0.23.1 без потери данных; проверено на POCO X6 5G (Android 16) — импорт профиля, подключение по RIVET/S1 к `192.168.88.17:18443`, туннель `10.79.0.250`, статус «Туннель активен · DNS через туннель», отключение и повторное подключение подтверждены на сервере (`online=false` → `online=true`). В выпуск входят Android Full и Client (по 4 APK), Windows Full ZIP и серверный архив; Linux-пакеты и Windows Client не входят. Проверены RIVET/S1, сборка Windows, подпись APK; H3, AWG, Xray, Cloak и публичный IPv6 в 0.24.0 не перепроверялись, iOS не собирался. [Подробности](docs/compatibility/0.24.0.ru.md).

EN: 0.24.0 fixes the server installer. The 0.23.1 package could not be installed: the `nat POSTROUTING` rule was built with an input interface and `iptables` replied `Can't use -i with POSTROUTING`; on an IPv6-only host `status` and the statistics timer also failed because `counters()` ran `wg show xio0` before the interface existed. The `-i` scope now stays in `FORWARD` only, and `counters()` skips absent interfaces. Verified by a live install on Debian 13 (LXC, `fr-host.fr`): bootstrap 0, `init` ok, `recipeVersion` 25, unit active. Android: XIO Full 0.24.0 installs in place over 0.23.1 without data loss; verified on a POCO X6 5G (Android 16) — profile import, RIVET/S1 connection to `192.168.88.17:18443`, tunnel `10.79.0.250`, state "Tunnel active · DNS through the tunnel", disconnect and reconnect confirmed on the server (`online=false` -> `online=true`). The release contains Android Full and Client (four APKs each), the Windows Full ZIP and the server archive; Linux packages and the Windows Client are not included. Verified: RIVET/S1, the Windows build, APK signatures; H3, AWG, Xray, Cloak and public IPv6 were not re-tested in 0.24.0, iOS was not built. [Details](docs/compatibility/0.24.0.en.md).


## 0.23.1 — 2026-10-31, проверка соединения без сайта, живой контроль связи, IPv6-payload

RU: проверка соединения больше не требует внешнего сайта. Туннель подтверждается свежим обменом, счётчиками трафика и DNS-запросом через туннель; опрос сайта стал необязательным и по умолчанию выключен (в настройках — «Проверять доступность сайта»). Выбор маршрута: сначала выбранный профиль, затем варианты того же endpoint с другим протоколом, затем остальные профили — заблокированный протокол меняется раньше, чем точка входа. Добавлен живой контроль связи: пока владелец хочет туннель, сторож раз в 15 с проверяет линию, при двух промахах переподключается и повторяет с паузой 5/15 с, пока сервер не вернётся; после восстановления счётчики продолжают расти. Проверено на POCO X6: остановка входа → «Повторное подключение…», подъём → восстановление за 15 с. Впервые проверен сквозной IPv6-payload: сервер на VPS-721137 с глобальным IPv6 `2a0c:b641:1a0:800::2a2`, клиент поднимает `fd79:1::fe/128` внутри туннеля, `ping6` и `wget -6` проходят через туннель (ответ — глобальный адрес VPS, NAT66). Собраны Android (Client и Full), Windows и Ubuntu; iOS не собран. Проверка сборки и хеши: [`verification-0.23.1.json`](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/verification-0.23.1.json). [Совместимость](docs/compatibility/0.23.1.ru.md).

EN: the connection check no longer requires an external site. The tunnel is confirmed by a fresh exchange, traffic counters and a DNS lookup through the tunnel; the site probe is optional and off by default (Settings → "Check site availability"). Route selection: the selected profile first, then same-endpoint variants with another protocol, then other profiles — a blocked protocol is switched before the entry point changes. A live link watchdog was added: while the owner wants the tunnel, it verifies the link every 15 s, reconnects after two misses and retries with 5/15 s backoff until the server returns; after recovery the counters keep growing. Verified on POCO X6: stopping the entry → "Reconnecting…", starting it → recovery within 15 s. End-to-end IPv6 payload was verified for the first time: the server on VPS-721137 with global IPv6 `2a0c:b641:1a0:800::2a2`, the client raises `fd79:1::fe/128` inside the tunnel, and `ping6` plus `wget -6` pass through the tunnel (the answer is the VPS global address, NAT66). Built: Android (Client and Full), Windows and Ubuntu; iOS not built. Build verification and hashes: [`verification-0.23.1.json`](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/verification-0.23.1.json). [Compatibility](docs/compatibility/0.23.1.en.md).

## 0.23.0 — 2026-10-26, переименование x1o → XIO

RU: сквозное переименование: пакеты `app.xio.client`/`app.xio.xio`, Dart-пакет `xio`, `XioVpnService`, серверные пути `xio-managed`/`/etc/xio`, серверные интерфейсы `xio0`/`xioawg0`, `xioTheme`, `libxio-awg.so`, `xio-server.tar.gz`. Клиентский помощник по-прежнему поднимает устройство `xio019` — это имя не менялось. Отдельная установка не нужна: `app.xio.client` существует с 0.22.4, Android обновляет приложение поверх, профили переносятся экспортом/импортом; приём `x1o://` сохранён. В этой же сборке: исправлен повторный импорт профиля и добавлено правило IPv6-firewall для Windows (правило `remoteip=::/1,8000::/1`; сам шаг настройки firewall на Windows остаётся проблемным — см. «Ограничения» в README). Собраны Android, Windows и Ubuntu (Ubuntu — `.deb`/`.tar.gz`, сборка на Debian 13, запуск GUI не проверялся); iOS не собран. Проверка сборки и хеши: [`verification-0.23.0.json`](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/verification-0.23.0.json). [Совместимость](docs/compatibility/0.23.0.ru.md).

EN: end-to-end rename: packages `app.xio.client`/`app.xio.xio`, Dart package `xio`, `XioVpnService`, server paths `xio-managed`/`/etc/xio`, server interfaces `xio0`/`xioawg0`, `xioTheme`, `libxio-awg.so`, `xio-server.tar.gz`. The client helper still creates device `xio019` — that name did not change. A separate install is not required: `app.xio.client` has existed since 0.22.4, Android updates in place, profiles move by export/import; `x1o://` import is still accepted. Also in this build: profile re-import fixed, and the Windows IPv6 firewall rule added (`remoteip=::/1,8000::/1`; the Windows firewall setup step itself remains problematic — see Limitations in README). Built: Android, Windows and Ubuntu (Ubuntu `.deb`/`.tar.gz`, built on Debian 13, GUI launch not tested); iOS not built. Build verification and hashes: [`verification-0.23.0.json`](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/verification-0.23.0.json). [Compatibility](docs/compatibility/0.23.0.en.md).

## 0.22.5 — 2026-10-26, client prerelase / предрелиз клиента

RU: исправлен повторный импорт клиентского профиля после удаления (удаление профиля больше не оставляет висячую ссылку в записи пользователя; добавлен регрессионный тест). Исправлена настройка firewall в Windows-помощнике: netsh не принимает `remoteip=::/0`, вместо него `::/1,8000::/1`. Впервые выполнена нативная проверка Windows x64: туннель AmneziaWG через Wintun, адрес 10.78.0.7/32, трафик идёт. На тестовом стенде Debian проверены AmneziaWG (IPv4 и IPv6 endpoint) и RIVET/H3+S1 на физическом Android; Xray/REALITY не подключается — несовместимость ядра клиента и шлюза, порог `minClientVer` не помогает. Публичный IPv6 и iOS по-прежнему не проверены. [Подробности](docs/compatibility/0.22.5.ru.md).

EN: fixed re-importing a client profile after deletion (removing a profile no longer leaves a dangling user reference; regression test added). Fixed the Windows helper firewall setup: netsh rejects `remoteip=::/0`, so `::/1,8000::/1` is used. First native Windows x64 check: AmneziaWG tunnel over Wintun, 10.78.0.7/32, traffic flows. On the Debian test stand AmneziaWG (IPv4 and IPv6 endpoints) and RIVET/H3+S1 were verified on a physical Android; Xray/REALITY does not connect — the client core and gateway are incompatible, and lowering `minClientVer` does not help. Public IPv6 and iOS remain unverified. [Details](docs/compatibility/0.22.5.en.md).

## 0.22.4 — 2026-10-24, client prerelease

RU: жёлто-оранжевая тема и все иконки клиента; зелёное оформление полного приложения сохранено. Подписанные Android APK, отдельные Windows/Ubuntu сборки, изолированная подготовка iOS. Раздельные desktop-хранилища. Проверка переноса всех пяти профилей через AppStore и строгий контроль неполной матрицы движков. Полная протокольная совместимость ещё не реализована; iOS без Mac/iPhone не собран. [Подробности](docs/compatibility/0.22.4.ru.md).

EN: yellow-orange client theme/icons, full app green preserved. Signed Android APKs, separate Windows/Ubuntu candidates, isolated iOS preparation. Separate desktop stores. Five-profile AppStore round-trip tests and a strict incomplete-engine parity gate. Full protocol compatibility remains unimplemented; no iOS build without Mac/iPhone. [Details](docs/compatibility/0.22.4.en.md).

## 0.22.3 — 2026-10-23, prerelease

RU: оба APK0.22.3+5012 проверены на POCO/Android16 через IPv4 VPS; пять протоколов, раздельные маршруты, квота/создание/отзыв субклиента и экспорт без серверных SSH-ключей. Исправлены DNS, права API, Android FileProvider и проверка Xray до TUN. Серверная ревизия24. Публичный IPv6 остаётся непроверенным.

EN: both APKs0.22.3+5012 physically checked on POCO/Android16 over the authorized IPv4 VPS; five transports, routing, subclient quota/create/revoke and SSH-free exports. DNS, API permissions, FileProvider and pre-TUN Xray HTTPS checks fixed. Recipe24; public IPv6 remains unverified.

## 0.22.2 — 2026-10-23

- Отдельный Android-клиент для готовых серверов, общий главный экран, переключение серверов и раздельное туннелирование.
- Субклиенты с ограниченным API-доступом: серверная квота, отзыв своих клиентов, сохранение незавершённой операции.
- Root/admin SSH-ключи не экспортируются клиенту; серверная ревизия 21.
- Separate Android client for existing servers, shared home UI, server switching and split tunnelling.
- Scoped subclients: server-enforced quota, own-child revocation and durable pending operations.
- No root/admin SSH key export to clients; server recipe 21.
- Local checks passed; new client/live account API deployment and physical-device validation remain pending.

## 0.22.1 · 2026-10-21

- RU: Исправлена активация нового пользователя Cloak; серверный пакет — ревизия 20. Все пять протоколов отдельно проверены на физическом Android. [Отчёт](docs/verification/android-physical-2026-10-21.ru.md).
- EN: Fixed new Cloak user activation; server package revision 20. All five protocols individually checked on physical Android. [Report](docs/verification/android-physical-2026-10-21.en.md).

# XIO 0.21.0 — 2026-10-19

RU: GitHub и «Поделиться приложением» в «О XIO»; проверка обновлений в настройках приложения, пропуск отдельного релиза, случайное недельное расписание. Подпись Ed25519 и проверка SHA-256 перед установкой. Исправлена целевая ОС Windows в сборке через Wine; добавлена проверка запущенного ядра. Добавлены зависимости EGL/GLES для чистой Ubuntu. Системная установка Android/Ubuntu, обновление ZIP в Windows с резервной копией. Фоновая проверка метаданных Android. Сохранены платформенные ограничения iOS и Google Play.

EN: GitHub and Share app in About XIO; application update checks, skip-release choice and randomized weekly scheduling. Ed25519 manifest signature and package SHA-256 verification. Corrected the Windows kernel target for Wine packaging and added a runtime target check. Declared EGL/GLES dependencies for clean Ubuntu installations. Android/Ubuntu system installation, Windows ZIP replacement with backup. Android background metadata checks. iOS and Google Play distribution limits remain explicit.

[Блог / Blog](docs/blog/2026-10-19-updates.md) · [RU](docs/ru/updates.md) · [EN](docs/en/updates.md).

# Public launch — 2026-10-18

RU: Репозиторий открыт. Добавлены topics, Discussions и русская/английская публикации Telegraph. Код и версия приложения не менялись.

EN: Repository made public. Added topics, Discussions and Russian/English Telegraph introductions. Application code and version are unchanged.

[Блог / Blog](docs/blog/2026-10-18-public-launch.md).

# Documentation 1.0 — 2026-10-18

RU: Подробная двуязычная библиотека RIVET/H3 и RIVET/S1, схемы, графики, источники данных и эксплуатационные ограничения. Код приложения 0.20.0 не изменён.

EN: Detailed bilingual RIVET/H3 and RIVET/S1 library, diagrams, charts, evidence inputs and operational boundaries. Application 0.20.0 code is unchanged.

[Блог / Blog](docs/blog/2026-10-18-rivet.md).

# Changelog

## 0.22.0 — 2026-10-19

RU: удалены отдельные WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale; «Протоколы» перенесены в «Соединение». Добавлены раздача через VPN с root на Android и экспериментальная Windows ICS, миграция управляемого сервера с откатом, проверенный импорт XHTTP/VLESS Encryption и два исправления гонок Xray. Названия загрузок типовые. Переписаны RU/EN инструкции. [Статья](docs/blog/2026-10-19-restricted-networks.md).

EN: retired standalone WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale; moved Protocols to Connection. Added rooted Android tethering and experimental Windows ICS, managed-server migration with rollback, checked XHTTP/VLESS Encryption import and two Xray race fixes. Generic download names and rewritten RU/EN guides. [Article](docs/blog/2026-10-19-restricted-networks.md#xio-022-allowlists-xhttp-and-managed-server-updates).
 / История изменений

## 0.20.0

- Moved Help and FAQ, and Licence and responsibility into About XIO. / Справка, FAQ, лицензия и ответственность перенесены в «О XIO».
- Grouped engine information under Protocols. / Информация о движках собрана в подразделе «Протоколы».
- Moved Diagnostics and the session log into Connection settings. / Диагностика и журнал перенесены в настройки соединения.
- Added Russian and English repository documentation, navigation diagrams and release guidance. / Добавлены русская и английская документация, схемы навигации и инструкции по загрузке.

This update changes shared UI navigation. It does not add a new engine or establish additional security guarantees. / Обновление меняет общую навигацию. Новые движки и дополнительные гарантии безопасности не заявляются.

## 0.19.0

Ubuntu and Windows clients; iOS source integration. See [platform details](CROSS-PLATFORM-0.19.ru.md). / Клиенты Ubuntu и Windows, исходная интеграция iOS.

## 0.18.0

Android release, multi-engine client and distribution package. See [historical notes](history/README.0.18.0.ru.md). / Выпуск Android, клиент нескольких протоколов и комплект распространения.


Матрица пяти протоколов в обоих приложениях (20 HTTPS-проверок) выполнена на сборке 5011. В финальной 5012 нативное ядро/AAR не менялось: добавлены журналы жизненного цикла плитки без секретов. На 5012 отдельно проверены подключение/отключение основной кнопкой плитки, независимый HTTPS через VPN и контроль Xray в клиенте. Это не повтор всей матрицы на 5012.

The five-protocol matrix in both apps (20 HTTPS checks) ran on build 5011. Final build 5012 uses the unchanged native engine/AAR and adds secret-free tile lifecycle logs. Build5012 separately passed the tile primary connect/disconnect commands, independent VPN HTTPS and a client Xray control. This does not represent a rerun of the entire matrix on 5012.
