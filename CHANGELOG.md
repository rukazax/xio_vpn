# XIO changes / Изменения

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

EN: retired standalone WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale; moved Protocols to Connection. Added rooted Android tethering and experimental Windows ICS, managed-server migration with rollback, checked XHTTP/VLESS Encryption import and two Xray race fixes. Generic download names and rewritten RU/EN guides. [Article](docs/blog/2026-10-19-restricted-networks.md#english).
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
