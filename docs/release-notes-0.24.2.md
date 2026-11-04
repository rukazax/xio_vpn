# XIO 0.24.2+5019+5019 — каскад, тише батарея и −7 МиБ APK

> Двуязычные заметки: русский блок идёт первым, английский — во второй половине файла.
> Матрица платформ и ограничения: [0.24.2.ru.md](compatibility/0.24.2.ru.md) · [0.24.2.en.md](compatibility/0.24.2.en.md)
> 🇬🇧 [English version](#english)

## Русский

0.24.2 — это встреча двух линий работы. Ветка `release-0.24.0` (то, что раньше уходило в rc13) принесла
фикс файлового дескриптора, Xray-конфиг напрямую в protobuf, готовый серверный пакет и каскад двух
серверов. Работа по main добавила вторую половину каскада, сабсет CJK-шрифта, честный клиентский
конвейер сборки, экономию батареи и герметичный набор тестов. Всё это — один выпуск.

### 🚀 Что нового

#### Что нового в 0.24.2 (обновление от 04.11)

Обновление того же выпуска: к первому комплекту 0.24.2 добавились выбор стороннего DNS, экран
MTProto-прокси, настройки поведения (автозапуск, автоподключение, скриншоты) и IPv4-exit в мастере
установки. Номера версии и `versionCode` не менялись (0.24.2+5019) — APK пересобраны, подпись та же
(`e4e81b12…c9671`), поэтому обновление ставится поверх.

- **🌐 Выбор стороннего DNS.** Настройки → «Соединение» → **«DNS-резолвер»**: готовые наборы
  (AdGuard DNS, Quad9, Cloudflare, Google Public DNS) или два своих адреса — IPv4, IPv6 или домен.
  Выбор записывается в новые AWG-профили и виден в мастере установки; сервер как DNS при этом не
  используется. Если выбрать только IPv6-адреса, экран честно предупреждает: без IPv6-выхода у
  сервера имена не разрешатся. Кадр — [`docs/screenshots/settings-dns.png`](screenshots/settings-dns.png).
- **✈️ MTProto-прокси для Telegram.** Настройки → **«Telegram-прокси (MTProto)»**: приложение хранит
  ссылку `tg://proxy?…`, проверяет её формат, копирует и отдаёт в Telegram. Прокси работает только
  для Telegram и не видит остальной трафик; ссылка даёт доступ к прокси, но не к аккаунту, и её не
  стоит публиковать. Шаблон ссылки:

  ```
  tg://proxy?server=<адрес>&port=<443>&secret=ee<32 hex-символа>
  ```

  Порядок включения на телефоне: скопировать ссылку → Telegram → «Настройки» → «Данные и память» →
  «Прокси» → «Добавить прокси» → **MTProto** → вставить ссылку → включить «Использовать прокси».
  Кадр — [`docs/screenshots/settings-mtproto.png`](screenshots/settings-mtproto.png).
- **⚙️ Автозапуск, автоподключение и разрешение скриншотов.** Настройки → «Приложение»:
  «Автозапуск при загрузке устройства» (приложение поднимается само после перезагрузки; без
  разрешения на уведомления подключение не поднимается), «Автоподключение после запуска» (выбранный
  профиль поднимается при открытии приложения, если туннель ещё не активен) и «Разрешить скриншоты»
  (по умолчанию **выключено**: экраны с ключами, профилями и SSH-доступом защищены `FLAG_SECURE`).
  Кадр — [`docs/screenshots/settings-behaviour.png`](screenshots/settings-behaviour.png).
- **🧭 Каскад с IPv4-exit.** В мастере установки сервера поле «Exit-сервер» теперь принимает
  **IPv4-адрес** наравне с IPv6 (`81.177.142.37` или `2a0c:b641:1a0:800::2a2`): IPv6 — каскад
  только для IPv6-трафика, IPv4 — весь трафик через зарубежный exit. Второе поле — диалог «Серверы
  каскада» — по-прежнему IPv6-адрес: транспорт `ssh -w 0:0` поднимается по IPv6. Кадры —
  [`cascade-configured.png`](screenshots/cascade-configured.png) и
  [`cascade-servers-dialog.png`](screenshots/cascade-servers-dialog.png).

**🩹 Старт больше не зависит от нативного слоя.** `AppStore.load()` вызывается через `unawaited`,
и любой `PlatformException` из нативных методов (`setAutostart`, `setAutoConnectOnStart`,
`setConsent`, `secureScreen`) оставлял приложение на сплэше навсегда: `ready` не наступал. Теперь
эти вызовы терпимы к ошибке, а `ready = true` и `notifyListeners()` стоят в `finally`. Найдено на
свежей установке APK, собранного со старым `android/` — там нативного `setAutostart` ещё не было.

**🔐 Дескриптор, из-за которого мобильный пакет падал случайно.** `tun.CreateUnmonitoredTUNFromFD`
заворачивает fd в `*os.File` **до** проверки `TUNGETIFF`; на неподходящем дескрипторе конструктор
возвращал ошибку, не закрыв объект, а `AwgTurnOn` на ошибочном пути закрывал тот же номер вторым
`unix.Close`. Номер успевал достаться следующему сокету, и финализатор брошенного `*os.File` закрывал
уже чужой сокет — отсюда случайные `i/o timeout` и `accept4: bad file descriptor` у Cloak
(`TestCloakCancellationAndProtection` и пара регрессионных сценариев: 15 падений из 30 прогонов).
Теперь конструктору отдаётся дубликат через `F_DUPFD_CLOEXEC`, исходный дескриптор закрывает сам
`AwgTurnOn`. Проверка: `GOGC=100` — 8 падений из 20 до фикса и 0 после, `GOGC=off` — 0 в обоих
случаях; после фикса пара тестов **30/30**, пакет `mobile` — **30/30**.

**📦 Xray-конфиг напрямую в protobuf.** Helper больше не тянет `xray-core/infra/conf` и `main/json`:
конфиг собирается в `core.Config` (`protocol/rivet/internal/xrayclient/xrayconf.go`). JSON-путь остался
под `-tags xrayjson` — это аварийный откат ровно прежнего размера.

| Метрика | Было | Стало |
| --- | --- | --- |
| `xio-tunnel.exe` (windows/amd64, `-trimpath -ldflags="-s -w"`) | 35 567 104 Б | **31 450 112 Б** (−4 116 992 Б, −11,58 %) |
| Символов `infra/conf` / `main/json` в бинаре | 261 / 4 | **0 / 0** |
| Пакетов исчезло из графа зависимостей | — | **145** |
| Эквивалентность профилей (3 протокола × 6 транспортов × 2 security) | — | **40/40** (побайтово тот же protobuf) |

Побочный эффект честный: `finalmask`, kcp/hysteria и `tlsSettings.echSockopt` теперь **отклоняются**
с `ErrConfig`, а не теряются молча. Набор закреплён тестом `TestKnownBehaviourDeltas` — любое
изменение поведения валит тест, а не тихо ломает туннель. `cmd/xraygateway` по-прежнему грузит
серверный JSON.

**🌍 Каскад двух серверов (bridge → exit).** Устройство приходит по IPv4 на bridge, тот держит
защищённый туннель только по IPv6 до второго сервера; трафик выходит из сети, где IPv6 — единственный
маршрут.

* отдельный экран **«Каскад»** — один, без прокрутки, целиком в экран телефона: три станции с флагами
  стран, линии состояния, пинг, «Переподключить»; при крупном системном шрифте всё сжимается, а не
  уезжает за экран;
* в форме установки сервера (Full) — галочка **«Включить каскад (по подписке)»**: после установки
  приложение показывает точную команду для bridge и открывает схему;
* серверная часть живёт **в контейнере**: `deploy/cascade/*` (`cascade-install.sh`, bridge/exit setup,
  `cascade-healthcheck.sh`, недельное обновление белых списков), MTU 1400 и BBR на `tun0` обеих
  сторон (1500 давал oversized-пакеты на exit);
* установка из терминала одной командой — `deploy/cascade/terminal-install.sh` скачивает установщик
  по HTTPS, проверяет sha256 и только потом запускает, лог пишется в `/var/log/xio-cascade-install.log`;
* веб-панель `server/webui` — TLS + Bearer-токен + cookie-сессия и CSRF-заголовок, по умолчанию
  `https://127.0.0.1:10443`; с одной страницы управляются службы, пользователи, каскад, белые списки
  и здоровье хоста.

Подробности: [каскад](cascade/README.md) · [веб-панель](../server/webui/README.md).

**⚡ Батарея и CPU: тот же туннель, меньше радио и перерисовок.**

* watchdog больше не делает DNS-пробу каждые 15 секунд. Сначала читается статус (это вызов по
  method-channel, без радио); свежий handshake (≤150 с) или растущий счётчик **rx** уже доказывают,
  что туннель жив, а DNS-ответ — только запасной вариант. Считается именно rx: tx растёт даже когда
  пакеты уходят в чёрную дыру, и доверие к нему глушило бы нужные переподключения. При скрытом окне
  проба — не чаще **одной в 90 секунд**, но уже пропущенная проба подтверждается на следующем тике,
  поэтому задержка обнаружения обрыва осталась прежней (два промаха);
* `Engine.status()` больше не перезаписывает preferences на каждом опросе: активный id стирается
  только если он реально записан (`clearActiveId`), а в rivet-ветке профиль расшифровывается **один
  раз на согласованный протокол**, а не на каждый трёхсекундный опрос (`reconciledProtocol`,
  сбрасывается при connect/disconnect/DOWN). `handshake()` переиспользует JSON, уже прочитанный
  `status()` — вдвое меньше JNI-вызовов на опрос;
* трёхсекундный опрос уведомляет слушателей **только при реальном изменении** статуса (сравнение по
  значению), поэтому простаивающий экран больше не перерисовывается каждые три секунды; `load()` не
  воскрешает опрос после того, как окно скрыли;
* экран каскада останавливает тикер и таймеры шагов на paused/inactive, а анимация бегущих точек
  перерисовывает только painter: три станции переданы как `AnimatedBuilder.child`, холст закрыт
  `RepaintBoundary`.

**🛠️ Серверный пакет: ready-служба вернулась в архив.**

| Что | Было | Стало |
| --- | --- | --- |
| `readiness.py` и `xio-ready.service` в архиве | **нет** (пакет 0.24.0 не устанавливался) | **есть**, и упаковщик падает, если их забыли |
| `RECIPE` | 25 | **26** |
| Переводы строк текстовых членов (`*.py`, `*.json`, `*.sh`) | CRLF, если архив собирали на Windows-дереве | **всегда LF**, хеш считается после нормализации |
| Архив, собранный на Windows и на Linux | два разных файла | **один и тот же** байт-в-байт |

Ready-ответчик слушает **только** адреса шлюза туннеля (10.78.0.1 и 10.79.0.1, порт 7447): клиент
присылает 16 случайных байт, сервер отвечает 32 байтами (статус + `SHA-256(nonce)`). Ни HTTP, ни
прокси, ни усилителя трафика из этого не сделать. Смысл простой: «мои пакеты вышли через туннель и
дальняя сторона действительно ответила» — без обращения к чужим сайтам. `update.py` принимает 25 как
источник миграции, поэтому установленные хосты обновляются, а не переустанавливаются.

**📱 Размер: −7,1 МиБ APK и Client без серверного балласта.**

| Что | Было | Стало |
| --- | --- | --- |
| CJK-шрифт (мастер) | 16 437 364 Б | **7 535 252 Б** (−8,49 МиБ) |
| CJK-шрифт внутри APK | 13 591 379 Б | **6 109 214 Б** (−7 482 165 Б) |
| Full APK, arm64 | 57,9 МиБ (сборка без сабсета) | **≈50,8 МиБ** (расчётно: −7,1 МиБ, −12,3 %) |
| Client APK, arm64 | 57,4 МиБ (ручная сборка с серверным архивом) | **≈22,9 МиБ** (официальный `client/build.py`) |
| `assets/xio-server.tar.gz` в Client | 22 302 894 Б | **0** |

Сабсет пересобран из собственных исходников main, а не скопирован: корпус 25 986 символов по 13
локалям плюс GB2312/JIS X 0208/KS X 1001, 33 758 глифов, повторная сборка даёт те же 7 535 252 Б.
`tools/subset-cjk-font.py --check` проверяет, что каждый символ корпуса, который рисует мастер,
рисуется и из сабсета.

Клиент: `client/build.py` пинил `0.24.0+5017`, а `app/pubspec.yaml` ушёл на `0.24.1+5018`, поэтому
`prepare()` падал **до** записи — клиент собирали руками и в APK уезжал серверный архив. Пины
выровнены, а новый тест связывает `build.py`/`verify.py` с `pubspec.yaml`, чтобы дрейф падал в
тестах, а не в артефакте. Gradle дополнительно вырезает серверный payload в client-only сборке
(`--dart-define=XIO_CLIENT_ONLY=true`) по тому же keep-list, который проверяет `client/verify.py`.
Заодно удалён мёртвый код: `cascadeStageColor` и геттер `ink`.

Методика замеров и таблица компонентов — в [«Оптимизация и измерения 0.24.1»](optimization-0.24.1.ru.md).

**✅ Тесты: набор стал герметичным.**

| Что | Было | Стало |
| --- | --- | --- |
| `flutter test` на Debian | 197 passed / 10 skipped (main) | **213 passed / 10 skipped / 0 failed** |
| Новых тестов | — | **16**: 13 на каскад, профили и герметичность, 3 на батарею и опрос статуса |
| Внешний `openssl` | нужен трём наборам | **не нужен**: самоподписанные фикстуры в репозитории (2020–2120, SAN localhost/127.0.0.1/::1) |
| Запись картинок при прогоне | писала в `verification/` и `docs/images/` | только с `XIO_CAPTURE_IMAGES=1`; вёрстка проверяется всегда |

Новое покрытие: экран каскада **360×640 и 412×915 без overflow**, отмена таймеров шагов в `dispose`,
`CascadeFeatureGate`/`CascadeSubscription`, round-trip профиля через JSON и AppStore, guard мёртвых
импортов для `lib/` и `test/`, `ClientVersionPinTests` на пины версии.

### 📦 Состав выпуска

| Файл | Что это | Изменение к 0.24.1 |
| --- | --- | --- |
| `XIO-Full-0.24.2-android-arm64-v8a.apk` | Full, arm64-v8a | −7,1 МиБ шрифта |
| `XIO-Full-0.24.2-android-armeabi-v7a.apk` | Full, armeabi-v7a | то же |
| `XIO-Full-0.24.2-android-x86_64.apk` | Full, x86_64 | то же; на живом устройстве не запускался |
| `XIO-Full-0.24.2-android-universal.apk` | Full, arm + arm64 | ≈96 МиБ |
| `XIO-Client-0.24.2-android-arm64-v8a.apk` | Client, arm64-v8a | ≈22,9 МиБ вместо 57,4 |
| `XIO-Client-0.24.2-android-armeabi-v7a.apk` | Client, armeabi-v7a | то же |
| `XIO-Client-0.24.2-android-x86_64.apk` | Client, x86_64 | то же |
| `XIO-Client-0.24.2-android-universal.apk` | Client, arm + arm64 | без серверного архива и CJK |
| `XIO-Full-0.24.2-windows-x64.zip` | Windows 11 x64 | может быть собран от rc13 |
| `XIO-0.24.2-ubuntu-amd64.deb` | Ubuntu 22.04+ x64 | сборка на Debian 13 |
| `XIO-0.24.2-ubuntu-x64.tar.gz` | Ubuntu, переносимый | — |
| `xio-server-0.24.2.tar.gz` | сервер, recipe 26 | +`readiness.py`, +`xio-ready.service`, LF |
| `SHA256SUMS-0.24.2.txt` | контрольные суммы | — |

Размеры и SHA-256 точных файлов — в `SHA256SUMS-0.24.2.txt` рядом с релизом; числа «после» в таблице
размеров посчитаны из измеренных компонентов (сборка APK на этой машине заблокирована WDAC, см. ниже).

### ✅ Проверено

* сборка Android на Debian 13 (arm64): AAR собирается из текущих исходников (`libgojni.so`
  31 523 496 Б, `infra/conf` — 0 строк), повторный прогон даёт байт-в-байт тот же APK — конвейер
  детерминирован (проверено на сборке 0.24.1; 0.24.2 идёт тем же конвейером);
* APK: package `app.xio.xio`, `minSdk 26`, `targetSdk 36`, подпись `e4e81b12…c9671` (та же, что у
  0.24.0), `apksigner verify` и `zipalign -c -P 16 4` — OK;
* установка и запуск на POCO X6 5G (Android 16, arm64; сборка 0.24.1 из этой же линии кода): экран
  лицензии и согласия, главный экран, «Настройки», «О XIO»; `ANR`/`FATAL EXCEPTION` в logcat нет,
  процесс жив;
* `flutter analyze` — 0 замечаний; `flutter test` на Debian — 213 passed / 10 skipped / 0 failed;
* Go: `build`/`vet`/`test ./...` в обоих режимах тегов, кросс-сборки windows/android/darwin;
* Xray: эквивалентность 40/40 профилей, живой смоук `Parse`+`Start` на 10 профилях, локальные TLS- и
  XHTTP-туннели;
* серверный архив: 27 членов, `recipeVersion` 26, повторный прогон даёт тот же sha256, CRLF-дерево
  даёт тот же архив, replay установочной секции `bootstrap.sh` — 15 целей, missing=0;
* каскад на серверах: bridge 8/8 юнитов, exit 9/9 + `xio-cascade-exit`, `systemctl --failed` = 0,
  `ping -6` без потерь, IPv6-выход через exit отвечает;
* вёрстка каскада: экран без прокрутки в тестах 360×640 и 412×915, флаги и статус на месте.

### ⚠️ Не проверено

* **живое подключение именно 0.24.2** на телефоне: в 0.24.1 приложение ставили чисто и к серверу не
  подключались, последний живой прогон RIVET/S1 — 0.24.0 (31.10.2026, `192.168.88.17:18443`);
* **живой трафик через каскад**: у тестового bridge (81.177.142.37) нет глобального IPv6, поэтому
  туннель bridge → exit (2a0c:b641:1a0:800::2a2) физически не поднять;
* **локальная сборка и тесты на Windows** заблокированы WDAC/Smart App Control: `dartaotruntime.exe`,
  `gen_snapshot.exe`, `impellerc.exe` и `flutter_tester.exe` не запускаются (`WinError 4551`) — APK и
  тесты идут на Debian, Windows ZIP собирается отдельно;
* **Windows-сборка в этом релизе может быть от rc13** — если пересборка не успеет, ZIP останется
  прежним (тот же код каскада, без правок размера);
* **подписка и перебор серверов — заглушки**: `CascadeFeatureGate.enabled` всегда false,
  `CascadeServerPool` содержит один bridge/exit;
* **x86_64 ABI** собран, но на устройстве не запускался; **iOS** не собирался;
* публичный IPv6 от клиента до сервера в 0.24.2 не перепроверялся.

### ⬆️ Как обновиться

1. **Android.** Ставьте APK поверх: подпись и имена пакетов не менялись (`app.xio.xio` — Full,
   `app.xio.client` — Client), профили и данные сохраняются. На MIUI/HyperOS `adb install` может
   вернуть `INSTALL_FAILED_USER_RESTRICTED` — тогда:

   ```bash
   adb push XIO-Full-0.24.2-android-arm64-v8a.apk /data/local/tmp/xio.apk
   adb shell pm install -r -g /data/local/tmp/xio.apk
   ```

2. **Windows.** «Настройки → Приложение → Проверить обновления» либо распакуйте ZIP в отдельную папку
   и запустите `XIO.exe`. Перед обновлением выключите VPN.
3. **Ubuntu/Debian x64.** `.deb` — обычная системная установка (`pkexec`, `apt-get`), либо
   переносимый `.tar.gz`. Приложение ставится в `/opt/xio`.
4. **Сервер.** Проще всего — из приложения при выключенном VPN: обслуживание управляемого сервера
   само проверит ревизию и обновит пакет. Вручную — тем же bootstrap с пином дайджеста:

   ```bash
   curl -fsSLo xio-server.tar.gz \
     "https://github.com/rukazax/xio_vpn/releases/download/v0.24.2/xio-server-0.24.2.tar.gz"
   curl -fsSLo xio-bootstrap.sh \
     https://raw.githubusercontent.com/rukazax/xio_vpn/main/server/managed/bootstrap.sh
   sudo XIO_EXPECTED_ARCHIVE_SHA256="<sha256 из SHA256SUMS>" \
     bash xio-bootstrap.sh < xio-server.tar.gz
   ```

5. **Каскад.** На новом bridge/exit — одной командой из
   [`deploy/cascade`](../deploy/cascade/README.md); если каскад уже стоит, обновление идёт тем же
   серверным пакетом.

Пользователи, ключи и профили при обновлении не пересоздаются: `RECIPE` 26 применяет миграцию с 25.
Если вы ставили rc13 — это тот же код каскада и фиксов, плюс работа по main; обновление обычное.

---

## English

0.24.2 is where two lines of work meet. The `release-0.24.0` branch (what used to ship as rc13) brings
the file-descriptor fix, the Xray config built directly in protobuf, a working server package and the
two-server cascade. Main-side work adds the second half of the cascade, the CJK font subset, an honest
client build pipeline, battery savings and a hermetic test suite. All of it lands as one release.

### 🚀 What's new

#### What's new in 0.24.2 (04.11 update)

A refresh of the same release: the first 0.24.2 payload gains a third-party DNS choice, an MTProto
proxy screen, behaviour settings (autostart, auto-connect, screenshots) and an IPv4 exit in the setup
wizard. Version and `versionCode` are unchanged (0.24.2+5019) — the APKs were rebuilt under the same
certificate (`e4e81b12…c9671`), so the update installs over the previous build.

- **🌐 Third-party DNS choice.** Settings → "Connection" → **"DNS resolver"**: ready-made sets
  (AdGuard DNS, Quad9, Cloudflare, Google Public DNS) or two addresses of your own — IPv4, IPv6 or a
  domain. The choice is written into new AWG profiles and shown in the install wizard; the server is
  never used as DNS. Choosing IPv6-only addresses warns honestly: without an IPv6 egress on the
  server the names will not resolve. Frame — [`docs/screenshots/settings-dns.png`](screenshots/settings-dns.png).
- **✈️ MTProto proxy for Telegram.** Settings → **"Telegram proxy (MTProto)"**: the app stores a
  `tg://proxy?…` link, validates the format, copies it and hands it to Telegram. The proxy serves
  Telegram only and never sees the rest of the traffic; the link grants proxy access, not account
  access, and should not be published. Link template:

  ```
  tg://proxy?server=<address>&port=<443>&secret=ee<32 hex chars>
  ```

  On the phone: copy the link → Telegram → "Settings" → "Data and Storage" → "Proxy" → "Add proxy"
  → **MTProto** → paste the link → enable "Use proxy". Frame —
  [`docs/screenshots/settings-mtproto.png`](screenshots/settings-mtproto.png).
- **⚙️ Autostart, auto-connect and screenshot permission.** Settings → "Application": "Autostart on
  device boot" (the app starts itself after a reboot; without the notification permission the tunnel
  stays down), "Auto-connect after launch" (the selected profile is raised when the app opens and the
  tunnel is not active yet) and "Allow screenshots" (**off** by default: screens with keys, profiles
  and SSH access are `FLAG_SECURE`). Frame —
  [`docs/screenshots/settings-behaviour.png`](screenshots/settings-behaviour.png).
- **🧭 Cascade with an IPv4 exit.** In the server setup wizard the "Exit server" field now takes an
  **IPv4 address** as well as IPv6 (`81.177.142.37` or `2a0c:b641:1a0:800::2a2`): IPv6 means a
  cascade for IPv6 traffic only, IPv4 routes all traffic through a foreign exit. The second field —
  the "Cascade servers" dialog — still expects an IPv6 address: the `ssh -w 0:0` transport comes up
  over IPv6. Frames — [`cascade-configured.png`](screenshots/cascade-configured.png) and
  [`cascade-servers-dialog.png`](screenshots/cascade-servers-dialog.png).

**🩹 Startup no longer depends on the native layer.** `AppStore.load()` runs through `unawaited`, so
any `PlatformException` from a native method (`setAutostart`, `setAutoConnectOnStart`, `setConsent`,
`secureScreen`) left the app on the splash screen forever: `ready` never became true. Those calls now
tolerate the error and `ready = true` / `notifyListeners()` sit in `finally`. Found on a fresh install
of an APK built against a stale `android/` that had no native `setAutostart` yet.

**🔐 The descriptor that made the mobile package fail at random.** `tun.CreateUnmonitoredTUNFromFD`
wraps the fd in an `*os.File` **before** it validates `TUNGETIFF`; on a descriptor that is not a TUN it
returns an error without closing that object, and `AwgTurnOn` closed the same number again with a
second `unix.Close`. The number then went back to the allocator and was handed to the next socket,
while the abandoned `*os.File` finalizer closed it later — hence random `i/o timeout` and
`accept4: bad file descriptor` in Cloak (`TestCloakCancellationAndProtection` plus a pair of regression
scenarios: 15 failures in 30 runs). The constructor now receives a duplicate made with
`F_DUPFD_CLOEXEC`, and `AwgTurnOn` closes the original descriptor itself. Evidence: `GOGC=100` — 8
failures in 20 runs before the fix, 0 after; `GOGC=off` — 0 either way; the fixed pair is **30/30** and
the whole `mobile` package is **30/30**.

**📦 Xray config directly in protobuf.** The helper no longer links `xray-core/infra/conf` or
`main/json`: the config is assembled into `core.Config`
(`protocol/rivet/internal/xrayclient/xrayconf.go`). The JSON path stays behind `-tags xrayjson` as an
exact-size emergency rollback.

| Metric | Before | After |
| --- | --- | --- |
| `xio-tunnel.exe` (windows/amd64, `-trimpath -ldflags="-s -w"`) | 35 567 104 B | **31 450 112 B** (−4 116 992 B, −11.58 %) |
| `infra/conf` / `main/json` symbols in the binary | 261 / 4 | **0 / 0** |
| Packages gone from the dependency graph | — | **145** |
| Profile equivalence (3 protocols × 6 transports × 2 security) | — | **40/40** (byte-identical protobuf) |

The trade-off is explicit: `finalmask`, kcp/hysteria and `tlsSettings.echSockopt` are now **rejected**
with `ErrConfig` instead of silently losing fields. The set is pinned by `TestKnownBehaviourDeltas`, so
any behaviour change fails a test instead of quietly breaking a tunnel. `cmd/xraygateway` still loads
the server JSON.

**🌍 Two-server cascade (bridge → exit).** The device arrives over IPv4 at the bridge; the bridge keeps
a protected IPv6-only tunnel to the second server, and traffic leaves from a network where IPv6 is the
only route.

* a dedicated **Cascade** screen — one screen, no scrolling, fits the phone: three stations with country
  flags, state lines, ping, "Reconnect"; with large system fonts everything shrinks instead of
  overflowing;
* in the server install form (Full) a **"Enable cascade (subscription)"** checkbox: after the install
  the app shows the exact command for the bridge and opens the diagram;
* the server side runs **in a container**: `deploy/cascade/*` (`cascade-install.sh`, bridge/exit setup,
  `cascade-healthcheck.sh`, weekly whitelist refresh), MTU 1400 and BBR on `tun0` on both sides (1500
  produced oversized packets on the exit);
* one-command terminal install — `deploy/cascade/terminal-install.sh` downloads the installer over
  HTTPS, verifies its sha256 and only then runs it, logging to `/var/log/xio-cascade-install.log`;
* web panel `server/webui` — TLS + Bearer token + cookie session and a CSRF header, by default
  `https://127.0.0.1:10443`; one page manages services, users, the cascade, whitelists and host health.

Details: [cascade](cascade/README.md) · [web panel](../server/webui/README.md).

**⚡ Battery and CPU: same tunnel, less radio and fewer repaints.**

* the watchdog no longer fires a DNS probe every 15 seconds. It reads the status first (a
  method-channel call, no radio); a fresh handshake (≤150 s) or a moving **rx** counter already proves
  the tunnel carries payload, and a DNS answer is only the fallback. Only rx counts: tx advances even
  when packets leave into a black hole, and trusting it would suppress the reconnects the watchdog
  exists for. While the window is hidden the probe is budgeted to **one per 90 seconds**, but a probe
  that already missed is confirmed on the next tick, so outage detection keeps the original two-miss
  latency;
* `Engine.status()` no longer rewrites the preferences file on every poll: the active id is cleared
  only when it is really stored (`clearActiveId`), and the rivet branch decrypts the profile **once per
  negotiated protocol** instead of on every three-second poll (`reconciledProtocol`, reset on
  connect/disconnect/DOWN). `handshake()` reuses the JSON already read by `status()`, halving the JNI
  calls per poll;
* the three-second status poll notifies listeners **only when the status actually changed** (value
  equality), so an idle screen is no longer rebuilt every three seconds; `load()` no longer revives the
  poll after the window was hidden;
* the cascade screen stops its ticker and step timers on paused/inactive, and the running-dots
  animation rebuilds only the painter: the three station widgets are passed as `AnimatedBuilder.child`
  and the canvas sits behind a `RepaintBoundary`.

**🛠️ Server package: the readiness service is back in the archive.**

| What | Before | After |
| --- | --- | --- |
| `readiness.py` and `xio-ready.service` in the archive | **missing** (the 0.24.0 package would not install) | **present**, and the packager fails if they are absent |
| `RECIPE` | 25 | **26** |
| Line endings of text members (`*.py`, `*.json`, `*.sh`) | CRLF when packaged from a Windows checkout | **always LF**, hash computed after normalisation |
| Archive built on Windows vs Linux | two different files | **the same bytes** |

The readiness responder listens **only** on the tunnel gateway addresses (10.78.0.1 and 10.79.0.1,
port 7447): the client sends 16 random bytes and the server answers with 32 bytes (status +
`SHA-256(nonce)`). It cannot be turned into an HTTP proxy, a reflector or an amplifier. The point is
one question: "did my packets leave through the tunnel and did the far side really answer?" — without
touching the public internet. `update.py` accepts 25 as a migration source, so installed hosts upgrade
instead of reinstalling.

**📱 Size: −7.1 MiB of APK and a client without server ballast.**

| What | Before | After |
| --- | --- | --- |
| CJK font (master) | 16 437 364 B | **7 535 252 B** (−8.49 MiB) |
| CJK font inside the APK | 13 591 379 B | **6 109 214 B** (−7 482 165 B) |
| Full APK, arm64 | 57.9 MiB (build without the subset) | **≈50.8 MiB** (computed: −7.1 MiB, −12.3 %) |
| Client APK, arm64 | 57.4 MiB (hand-built with the server archive) | **≈22.9 MiB** (official `client/build.py`) |
| `assets/xio-server.tar.gz` in Client | 22 302 894 B | **0** |

The subset is regenerated from main's own sources, not copied: a 25 986-character corpus across 13
locales plus GB2312/JIS X 0208/KS X 1001, 33 758 glyphs, and a rerun produces the same 7 535 252 B.
`tools/subset-cjk-font.py --check` verifies that every corpus character the master renders also renders
from the subset.

Client: `client/build.py` pinned `0.24.0+5017` while `app/pubspec.yaml` moved to `0.24.1+5018`, so
`prepare()` aborted **before** writing anything — the client was built by hand and the APK shipped the
server archive. The pins are aligned, and a new test ties `build.py`/`verify.py` to `pubspec.yaml` so
drift fails in tests instead of in the artifact. Gradle also strips the server payload in a client-only
build (`--dart-define=XIO_CLIENT_ONLY=true`) using the same keep-list that `client/verify.py` enforces.
Dead code was dropped along the way: `cascadeStageColor` and the `ink` getter.

Measurements and methodology: [Optimisation and measurements 0.24.1](optimization-0.24.1.ru.md).

**✅ Tests: the suite is hermetic now.**

| What | Before | After |
| --- | --- | --- |
| `flutter test` on Debian | 197 passed / 10 skipped (main) | **213 passed / 10 skipped / 0 failed** |
| New tests | — | **16**: 13 for cascade, profiles and hermeticity, 3 for battery and status polling |
| External `openssl` | required by three suites | **not needed**: self-signed fixtures in the repo (2020–2120, SAN localhost/127.0.0.1/::1) |
| Image writes during a run | wrote into `verification/` and `docs/images/` | only with `XIO_CAPTURE_IMAGES=1`; layout is always asserted |

New coverage: the cascade screen **at 360×640 and 412×915 without overflow**, cascade step timers
cancelled in `dispose`, `CascadeFeatureGate`/`CascadeSubscription`, profile round trip through JSON and
AppStore, a dead-import guard for `lib/` and `test/`, and `ClientVersionPinTests` on the version pins.

### 📦 Release payload

| File | What it is | Change vs 0.24.1 |
| --- | --- | --- |
| `XIO-Full-0.24.2-android-arm64-v8a.apk` | Full, arm64-v8a | −7.1 MiB of font |
| `XIO-Full-0.24.2-android-armeabi-v7a.apk` | Full, armeabi-v7a | same |
| `XIO-Full-0.24.2-android-x86_64.apk` | Full, x86_64 | same; not launched on a physical device |
| `XIO-Full-0.24.2-android-universal.apk` | Full, arm + arm64 | ≈96 MiB |
| `XIO-Client-0.24.2-android-arm64-v8a.apk` | Client, arm64-v8a | ≈22.9 MiB instead of 57.4 |
| `XIO-Client-0.24.2-android-armeabi-v7a.apk` | Client, armeabi-v7a | same |
| `XIO-Client-0.24.2-android-x86_64.apk` | Client, x86_64 | same |
| `XIO-Client-0.24.2-android-universal.apk` | Client, arm + arm64 | no server archive, no CJK font |
| `XIO-Full-0.24.2-windows-x64.zip` | Windows 11 x64 | may be built from rc13 |
| `XIO-0.24.2-ubuntu-amd64.deb` | Ubuntu 22.04+ x64 | built on Debian 13 |
| `XIO-0.24.2-ubuntu-x64.tar.gz` | Ubuntu, portable | — |
| `xio-server-0.24.2.tar.gz` | server, recipe 26 | +`readiness.py`, +`xio-ready.service`, LF |
| `SHA256SUMS-0.24.2.txt` | checksums | — |

Exact sizes and SHA-256 live in `SHA256SUMS-0.24.2.txt` next to the release; the "after" numbers in the
size table are computed from measured components (an APK build is blocked on this machine by WDAC, see
below).

### ✅ Verified

* the Android build on Debian 13 (arm64): the AAR is built from current sources (`libgojni.so`
  31 523 496 B, zero `infra/conf` strings) and a rerun reproduces the same APK bytes — the pipeline is
  deterministic (verified on the 0.24.1 build; 0.24.2 goes through the same pipeline);
* the APK: package `app.xio.xio`, `minSdk 26`, `targetSdk 36`, signature `e4e81b12…c9671` (same as
  0.24.0), `apksigner verify` and `zipalign -c -P 16 4` — OK;
* install and launch on a POCO X6 5G (Android 16, arm64; the 0.24.1 build from this same code line):
  licence and consent screens, main screen, Settings, About; no `ANR` or `FATAL EXCEPTION` in logcat,
  the process stays alive;
* `flutter analyze` — 0 issues; `flutter test` on Debian — 213 passed / 10 skipped / 0 failed;
* Go: `build`/`vet`/`test ./...` under both tag sets, cross-builds for windows/android/darwin;
* Xray: 40/40 profile equivalence, a live `Parse`+`Start` smoke on 10 profiles, local TLS and XHTTP
  tunnels;
* the server archive: 27 members, `recipeVersion` 26, a rerun yields the same sha256, a CRLF tree yields
  the same archive, and a replay of the `bootstrap.sh` install section reaches 15 targets, missing=0;
* the cascade on the hosts: bridge 8/8 units, exit 9/9 plus `xio-cascade-exit`, `systemctl --failed` = 0,
  `ping -6` without loss, the IPv6 exit answers;
* cascade layout: the screen has no scrolling in the 360×640 and 412×915 tests, flags and status are in
  place.

### ⚠️ Not verified

* **a live connection on the 0.24.2 build itself**: on 0.24.1 the app was installed clean and never
  connected, and the last live RIVET/S1 run was 0.24.0 (2026-10-31, `192.168.88.17:18443`);
* **live traffic through the cascade**: the test bridge (81.177.142.37) has no global IPv6, so the
  bridge → exit tunnel (2a0c:b641:1a0:800::2a2) cannot physically come up;
* **local Windows builds and tests** are blocked by WDAC/Smart App Control: `dartaotruntime.exe`,
  `gen_snapshot.exe`, `impellerc.exe` and `flutter_tester.exe` do not start (`WinError 4551`); APKs and
  tests run on Debian and the Windows ZIP is built separately;
* **the Windows build in this release may come from rc13** — if the rebuild does not land in time, the
  ZIP stays as it was (same cascade code, without the size work);
* **subscription and server rotation are stubs**: `CascadeFeatureGate.enabled` is always false and
  `CascadeServerPool` holds one bridge/exit;
* **the x86_64 ABI** is built but not launched on a device; **iOS** was not built;
* public IPv6 from the client to the server was not re-tested for 0.24.2.

### ⬆️ How to update

1. **Android.** Install the APK in place: the signer and package names are unchanged (`app.xio.xio` for
   Full, `app.xio.client` for Client), profiles and data are preserved. On MIUI/HyperOS `adb install`
   may return `INSTALL_FAILED_USER_RESTRICTED`; use:

   ```bash
   adb push XIO-Full-0.24.2-android-arm64-v8a.apk /data/local/tmp/xio.apk
   adb shell pm install -r -g /data/local/tmp/xio.apk
   ```

2. **Windows.** Settings → Application → Check for updates, or unpack the ZIP into a separate folder and
   run `XIO.exe`. Turn the VPN off before updating.
3. **Ubuntu/Debian x64.** The `.deb` installs through the system installer (`pkexec`, `apt-get`), or use
   the portable `.tar.gz`. The app installs to `/opt/xio`.
4. **Server.** The easy path is from the app with the VPN off: managed-server maintenance checks the
   revision and updates the package. By hand, use the same bootstrap with a digest pin:

   ```bash
   curl -fsSLo xio-server.tar.gz \
     "https://github.com/rukazax/xio_vpn/releases/download/v0.24.2/xio-server-0.24.2.tar.gz"
   curl -fsSLo xio-bootstrap.sh \
     https://raw.githubusercontent.com/rukazax/xio_vpn/main/server/managed/bootstrap.sh
   sudo XIO_EXPECTED_ARCHIVE_SHA256="<sha256 from SHA256SUMS>" \
     bash xio-bootstrap.sh < xio-server.tar.gz
   ```

5. **Cascade.** On a new bridge/exit use the one-command install from
   [`deploy/cascade`](../deploy/cascade/README.md); an existing cascade is updated by the same server
   package.

Users, keys and profiles are not recreated during an update: `RECIPE` 26 applies the migration from 25.
If you were on rc13, this is the same cascade and fix code plus the main-side work; the update is
ordinary.

[Compatibility 0.24.2](compatibility/0.24.2.en.md) · [Changelog](../CHANGELOG.md)
