# XIO changes / Изменения

## 0.24.12+5029 — 17.11.2026

### Второй этап каскада ставится на сервер, который очистили перед установкой

- Следы на bridge `81.177.142.37`: в 18:35:58 очистка с галочкой «Очистить
  сервер перед установкой» выполнила `apt-get purge iptables libip6tc2 …
  openvpn` (эти пакеты пришли с управляемой установкой 16.11 и были записаны
  в квитанцию), после чего `xio-cascade-bridge-up.sh` упал на строке 48 с
  `iptables: command not found` (код 127), unit ушёл в `Restart=always`, а
  мастер показал общий отказ этапа.
- Оба этапа каскада теперь проверяют `ip`, `iptables`, `ip6tables`, `ssh`,
  `ping`, `sysctl` до записи файлов и ставят недостающее штатным менеджером
  (`apt-get` с `DPkg::Lock::Timeout=60`, `dnf` на RHEL-семействе), затем
  проверяют повторно. Не удалось — этап падает с именем инструмента.
- Проверка готовности этапа выполняет `exec 2>&1` и печатает хвост
  `journalctl`/`systemctl`, поэтому в сообщении видна настоящая причина
  (`iptables: command not found`, отказ unit), а не «bridge did not confirm
  readiness». Хвост вывода обрезается до шести непустых строк.
- `purge_packages` учитывает `SHARED_PACKAGES`: `iptables`, `ip6tables`,
  `iproute2`, `iproute`, `ca-certificates`, `openssh-client`,
  `openssh-server`, `curl` не удаляются, даже если их поставила предыдущая
  установка XIO. Принадлежащие XIO `wireguard-tools` и `openvpn` по-прежнему
  снимаются. Правка внесена в `server/managed/admin.py` и в ассет
  `app/assets/xio-admin.py`, регрессия закрыта тестом `test_host_tooling_survives_purge`.

### Проверки

- Живой этап 2 на паре `79e.ru` (bridge без `iptables`) → `103.102.135.124`
  (exit): `installed prerequisites: iptables`; `tun0 10.250.0.1/30 up`;
  `SSH TUN to 103.102.135.124: OK`; `ping 10.250.0.2: OK`.
- Трафик через каскад: помеченный сокет (`SO_MARK` `0x518`) выходит с адресом
  exit `103.102.135.124`.
- Повторный запуск этапа идемпотентен: `tools=ok`, туннель перезапускается,
  ping проходит.
- `flutter test` — 1167 passed, 27 skipped, 0 failed.
- `flutter analyze` — 0 ошибок; 3 предупреждения в файлах вне каскада
  (`lib/core.dart:3831`, `tool/issuance_vault_isolate.dart`,
  `test_legacy_reviewer_fixtures/`), существовали до выпуска.

## 0.24.11+5028 — 17.11.2026

### Установка: APK содержит движок ровно одной ABI

- Выпуск 0.24.10 отдавал fat-сборки по 75 МБ. В файле `armeabi-v7a` движок
  Flutter был только 32-битный, но каталоги `lib/arm64-v8a` (`libgojni.so`,
  `libc++_shared.so`, `libxio_openvpn.so`) тоже лежали внутри: система выбирала
  arm64 как `primaryCpuAbi`, не находила `libflutter.so`/`libapp.so`, и
  приложение устанавливалось, но падало при запуске. Воспроизведено на
  23122PCD1G: процесс есть, активити нет.
- Сборка идёт `flutter build apk --release --split-per-abi
  --target-platform android-arm64,android-arm` с
  `--android-project-arg force-version-code-ignoring-abi=true`: каждый APK
  содержит библиотеки только своей ABI (проверяется `unzip -l`), у обоих
  один `versionCode` 5028. Размер arm64 — 52,4 МБ вместо 79,5 МБ.

### Логирование и телеметрия выключены в релизе

- `XioDiag.log` в релизной сборке — no-op: ни файла, ни буфера, ни вызова
  MethodChannel; `install()` не ставит обработчики ошибок.
- Kotlin `Diag` в релизе не создаёт каталог и файл журнала, не ставит
  crash-handler: `init`, `append`, `snapshot`, `bundle`, `logcat` возвращают
  пусто.
- Все `android.util.Log` в коде приложения заменены на `XLog`, который пишет
  только при `BuildConfig.TEST_BUILD`. Тестовая сборка (`-PxioTestBuild=true`)
  по-прежнему ведёт журнал, снимает bundle и может выгрузить его в панель.
- Удалён geo-IP запрос к `ipapi.co`: флаг страны берётся только из профиля или
  сохранённого сервера. Правовые тексты (RU/EN) и `assets/help/privacy.*`
  обновлены — обещания отправить адрес сервера наружу больше нет.
- Остались только сетевые вызовы по действию пользователя: «Проверить каскад»
  (ipify/ifconfig), проверка соединения (по умолчанию выключена) и проверка
  обновлений с GitHub.

### Проверки

- `flutter test` — 1163 passed, 27 skipped, 0 failed.
- `flutter analyze` — 0 ошибок и предупреждений (46 info в `tool/`).
- На 23122PCD1G (Android 16): `adb install -r` — успех, запуск, подключение
  профиля `diag9009` (AmneziaWG), счётчики 16,6 кБ / 13,1 кБ, отключение без
  остатка `tun0`. `logcat` за всю сессию — ни одной строки с тегом `XIO`.

## 0.24.10+5027 — 17.11.2026

### Уточнение: при поднятом туннеле нельзя менять не только режим

- 0.24.9 написала «пока соединение поднято, режим менять нельзя». Это правда,
  но не вся: форма настроек соединения целиком плановая (проверка сайта, адрес
  проверки, таймаут, переподключение, режим — всё входит в план и receipt),
  поэтому при поднятом туннеле заблокирована кнопка «Сохранить», а не только
  переключатель режима (`workspace_ui.dart`, `client_main.dart` — «every
  connection setting in this form is plan-sensitive»).
- Новый текст: «Туннель активен. Сначала отключите VPN: пока соединение
  поднято, настройки соединения менять нельзя.» Переведён на все 13 языков.
  Поведение не менялось: тот же отказ `connected` и тот же `POLICY_BUSY`
  нативной стороне.
- Проверено на телефоне 23122PCD1G: при поднятом туннеле строка называет
  настройки, «Сохранить» остаётся неактивной; после «Отключиться» форма
  сохраняется и режим подтверждается.

## 0.24.9+5026 — 17.11.2026

### Экран режима называет настоящую причину отказа

- При поднятом туннеле «Настройка соединений» показывала «Изменение режима
  недоступно: другая операция ещё не завершена…», хотя никакой операции не шло:
  движок просто не даёт менять режим на живом соединении. Один код `busy`
  смешивал два разных отказа с разным действием пользователя.
- Отказ разделён: `busy` — идёт согласование, подключение или очистка (надо
  подождать), `connected` — поднятый туннель без незавершённой работы (надо
  отключиться). Нативной стороне оба по-прежнему отдают `POLICY_BUSY`, контракт
  политики не менялся.
- Текст для `connected`: «Туннель активен. Сначала отключите VPN: пока
  соединение поднято, режим менять нельзя.» Переведён на все 13 языков
  (884 записи в каждом каталоге).
- Наблюдение за связью (`_watchdog`) больше не считается работой: оно живёт
  ровно столько, сколько владелец хочет туннель, поэтому при здоровом
  соединении оно всегда есть. Раньше именно оно возвращало `busy` в этой ветке.
- Один предикат `_liveWorkBlocker()` используется геттером UI, сеттером режима и
  явным восстановлением, чтобы ответы не разъезжались.
- Тесты: `policy_mode_ui_store_test` ждёт `connected` и отсутствие старого
  текста; цикл локализации блокеров включает `connected`.

## 0.24.8+5025 — 17.11.2026

### Автоматический перебор маршрутов заработал

- Автоматический режим падал на втором кандидате с `POLICY_BUSY: VPN
  publication is active`. Причина не в протоколе и не в плане: гейт
  `PublicationLease` считал публикацией политики **живую активацию** туннеля
  (`current != null && !revoked`), а поле `current` не очищается, пока туннель
  поднят. Первый кандидат, который реально подключался, блокировал собственный
  же `save()` — выбор победившего профиля не публиковался, кандидат считался
  неудачным, туннель снимался, а остальные кандидаты оставались без receipt
  (`POLICY_UNSUPPORTED: The app must finish saving the connection policy first`).
  То есть перебор не работал ровно в том случае, ради которого он существует.
- `PublicationLease` получил явное состояние активации: `begin()` открывает
  окно установления соединения, `Engine.settleActivation(roundId)` закрывает его
  сразу после успешного `connect`. Резервирование политики теперь требует
  пустой набор запросов, отсутствие отмены, незавершённой активации, мутации
  конфигурации и предыдущей публикации — поднятый туннель больше не владеет
  полосой. `retire()`/`revoke()` закрывают окно аварийно.
- Проверено на телефоне 23122PCD1G: первый кандидат с закрытым портом падает за
  8.7 с, следующий (awg) поднимается за 761 мс, `activation settled` →
  публикация выбора (`reserve ok`) → туннель активен, ошибки нет. Обратный
  сценарий (xray → awg → rivet-s1) даёт выход `103.102.135.124` (Франция),
  прямой xray — `81.177.142.37` (РФ).
- Закреплено тестами: `test/policy_publication_api_test.dart` — перебор
  вызывает второго кандидата с тем же receipt и публикует победителя;
  `PolicyWiringTest` — реальный гейт: активация держит полосу до `settle`,
  после `settle` публикация проходит, при этом живой туннель не отзывается.

### Диагностика и тест-драйвер

- `connect: failed <протокол>` теперь пишет код и сообщение отказа, а не только
  тип исключения: без этого `POLICY_BUSY` выглядел одинаково для семи разных
  причин.
- Отказ регистрации подключения (`POLICY_BUSY`) пишется в журнал гейта
  (`policy-gate: connect register refused: …`).
- Тест-драйвер: `select` (`id`/`protocol`/`index`), `delete` (профиль по
  `id`/`protocol`), `connect` без `protocol` подключает **текущий** выбор вместо
  первого профиля списка, а `status` в ответе `connect` показывает список
  кандидатов и принятый профиль.

## 0.24.7+5024 — 17.11.2026

Промежуточная сборка 0.24.6+5023 того же дня отдельной записи не имеет: её
правки вошли сюда.

### REALITY не работал ни с одним клиентом

- Закреплённый `github.com/xtls/reality` разбирает первый полёт decoy-сайта в
  буфере 8 КиБ, а `www.microsoft.com` отдаёт TLS `Certificate` длиной 8273
  байта. Сервер не мог подставить сертификат и рвал рукопожатие у всех клиентов
  (официальный Xray 26.11.9, ядро приложения 26.7.28, любые ключи). Это выглядит
  как ошибка аутентификации, но является ограничением размера цели.
- `vendor/reality` — точная копия закреплённого модуля с буфером 17 КиБ, как в
  актуальном upstream; подключена через `replace` в `vendor/xray/go.mod` и
  `protocol/rivet/go.mod`. Криптография и формат не менялись; пересобран и
  развёрнут `xio-stack`, декой сохранён, профили не перевыпускались.

### Проба готовности роняла исправный туннель

- `XrayBackend.connect` ходил только на `checkSite` (по умолчанию
  `https://youtube.com`), который на выходе блокируется по SNI, и одна попытка
  съедала весь дедлайн. Теперь проба идёт по списку (сайт из плана →
  `www.google.com` → `api.ipify.org` → `www.cloudflare.com`) с общим бюджетом:
  достаточно одного успешного ответа.

### Политика после перезапуска больше не застревает

- На Android ожидаемое поколение берётся из READY-конверта журнала; свежий
  процесс его не знал и резервировал транзакцию с `expectedGeneration = null`,
  получая `POLICY_STALE` навсегда. Теперь `PolicyChannel.queryState` наблюдает
  несовпавший READY-конверт (снимая вложенную квитанцию), а
  `settleNativePending` закрывает и «живую» транзакцию.
- Реконсиляция после неудачной публикации читает CAS из документа на диске, а не
  из памяти, поэтому «durable snapshot changed by a newer publication» больше не
  блокирует каждую попытку.

### Тест-драйвер

- `xioTest`/`xioTest64` принимал не более 4000 символов — капсулы выдачи не
  проходили. Лимит поднят до 256 КиБ; добавлены команды `policy`, `import`,
  `config`; отладочный вывод импорта очищается от секретов.

## 0.24.5+5022 — 17.11.2026

### Каскад везёт все транспорты, а не только AWG

- Правило каскада было жёстко `iif xioawg0`: в туннель до exit уходил только
  AmneziaWG, а RIVET (kernel-TUN `xiorivet`) и Xray (userspace-прокси, своего
  интерфейса нет) продолжали выходить напрямую из РФ. Теперь входные интерфейсы
  обнаруживаются по префиксу `xio*`, и для каждого ставится
  `ip rule add iif … lookup 51888` (IPv4 и IPv6) плюс FORWARD-ACCEPT в обе
  стороны. Скрипты сноса симметричны: интерфейсы берутся из уже установленных
  правил, поэтому уборка работает и после исчезновения интерфейса.
- Xray: при заданном `XIO_CASCADE_MARK` freedom-outbound получает
  `sockopt.mark`, а юнит — `AmbientCapabilities`/`CapabilityBoundingSet`
  `CAP_NET_ADMIN`. Без переменной поведение прежнее: метки нет, bounding set
  пуст, песочница не ослаблена.
- `xio-cascade-bridge-{up,down}.sh` и встроенные в приложение копии теперь
  сверяются тестом `app/test/cascade_script_sync_test.dart`: раньше три копии
  разошлись молча и приложение ставило каскад только для AWG.

Проверено на живой паре: счётчик `iifname "xioawg0" oifname "tun0"` растёт;
Xray запущен с `sockopt.mark: 1304` и `cap_net_admin`, сервис `active`;
помеченный сокет в тех же условиях, в которых работает Xray (DynamicUser,
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, единственная
capability — `CAP_NET_ADMIN`), выходит через exit `103.102.135.124`.
Честная граница: сквозной прогон Xray-клиента через каскад не снимался — на
момент проверки подключённых Xray-пользователей не было.

### Тесты выпуска в WebUI

- `issue_user` — единственное место, где WebUI создаёт удалённую учётку, — не
  покрывался тестами. Добавлен `server/webui/test_issuance_unit.py`: точный
  набор полей managed-add, отказ без повтора при ошибке add,
  `INVALID_RESULT`+`outcomeUnknown` при сбое сборки профиля после успешного add
  и освобождение приватного материала после успеха.

## 0.24.4+5021 — 17.11.2026

### Мастер каскада из двух этапов

- Установка каскада вынесена в отдельный мастер: этап 1 — exit (tun0
  10.250.0.2/30, форвардинг, NAT44/NAT66, `PermitTunnel yes` в drop-in с
  проверкой `sshd -t`), этап 2 — bridge (ключ `/root/.ssh/xio_cascade`,
  авторизация на exit, `tun0` 10.250.0.1/30, политика `iif xioawg0` → таблица
  51888, SNAT, MSS clamp).
- Каждый этап показывает только те факты, которые прочитал с сервера; экран не
  пишет «Каскад поднят», пока bridge не подтвердил туннель (`ssh -w 0:0`,
  `ping 10.250.0.2`) и exit не ответил своим IPv4-выходом.
- Одиночный переключатель «каскад» с полем exit убран из диалога установки:
  установка XIO и установка каскада больше не смешаны в одном действии.
- Правило каскада дополнено `fwmark 0x518`: локально созданный трафик Xray и
  RIVET тоже может уходить через exit (правило `iif xioawg0` покрывало только
  AmneziaWG). В `-down.sh` правило удаляется.
- Проверка этапа 2 больше не гоняется с `Restart=always`: ожидание подъёма
  туннеля до 30 с вместо `sleep 3`.

### «Очистить сервер»

- Новый пункт в меню сервера, в настройках серверов и в диалоге подключения:
  удаляет все компоненты XIO (службы, профили, RIVET, каскад, панель, ключи,
  правила XIO, журнал установки XIO) и возвращает хост к состоянию до установки.
- Работает и на сервере без установленного XIO: bootstrap-маркер создаётся при
  необходимости, поэтому очистку можно сделать перед установкой.
- Сервер сам сообщает, что удалил, и возвращает список `remaining`; непустой
  список — это ошибка, а не сообщение об успехе. Общие пакеты ОС, чужие службы,
  чужие туннели и системный журнал не затрагиваются.
- Пока VPN активен, очистка не начинается: приложение сначала предлагает
  отключиться.

## 0.24.3+5020 — 17.11.2026

### Каскад телефон → VPS РФ → зарубежный VPS

- Главная страница показывает каскад с флагами стран: устройство, bridge и exit,
  фактический выходной IP и страну выхода.
- Проверка каскада с телефона: если SSH-сервер не сохранён, приложение честно
  проверяет фактический выходной адрес через `api.ipify.org` и сохраняет его.
- Новые поля профиля `cascadeExitIp`, `cascadeBridgeCountry`, `cascadeExitCountry`
  (Android `DurableDocument` допускает их в документе).
- Восстановление режима подключения: кнопка «Повторить согласование» больше не
  скрывается, пока сохранение считается незавершённым.
- Мобильный профиль: MTU 1280 и DNS 9.9.9.9 для каскада; на bridge добавлен
  MSS-clamp в сторону телефона.

### Серверная часть

- `deploy/cascade/native/` — идемпотентные скрипты и systemd-юниты:
  SSH TUN между bridge и exit, SNAT клиентов на bridge, NAT44/NAT66 на exit,
  IPv4 и IPv6, MSS-clamp, автозапуск и восстановление SSH-туннеля.
- Проверено на живых серверах: bridge `81.177.142.37` (RU), exit
  `103.102.135.124` (FR); выходной адрес телефона — `103.102.135.124`.

## Не выпущено — Android: первый коннект и согласование плана / Unreleased — Android first connect and plan reconciliation

RU: исправлена цепочка, из-за которой свежий Android-клиент не подключался к профилю веб-панели.
Reconcile на Android отправлял `expectedGeneration = null`, хотя READY-журнал требует точную
generation; теперь generation берётся из нативного READY-состояния. Нативный
`DurableDocument` не принимал четыре поля каскада (`cascadeHealthOk`, `cascadeHealthPingMs`,
`cascadeExitIpv6`, `cascadeCheckedAt`) — добавлены в optional-allowlist и в policy-фикстуры.
Первый коннект после импорта больше не уходит в легаси-путь без плана: при доступной policy
capability план согласуется до активации, даже если in-memory флаг версии ещё не выставлен.
Приоритет Android по умолчанию переведён с Xray на AmneziaWG: полный профиль подключается
с первого нажатия, RIVET/Xray остаются резервом. Проверено на POCO X6 5G (Android 16):
чистый импорт профиля `Telefon KA`, туннель `10.78.0.2`, handshake на сервере, выходной IP
`81.177.142.37`, смена Wi-Fi ↔ LTE без разрыва, полный `flutter test` — 1138 passed, 23 skipped.
[Подробности](docs/ANDROID-VALIDATION-20261117.md).

EN: fixed the chain that kept a fresh Android client from connecting to a web-panel profile.
Android reconcile sent `expectedGeneration = null` while the READY journal requires the exact
generation; it now comes from the native READY state. Native `DurableDocument` rejected four
cascade fields (`cascadeHealthOk`, `cascadeHealthPingMs`, `cascadeExitIpv6`, `cascadeCheckedAt`);
they are now in the optional allowlist and in the policy fixtures. The first connect after import
no longer takes the planless legacy path: when the policy capability is available, the plan is
reconciled before activation even if the in-memory versioned flag has not been set yet. Android's
default priority moved from Xray to AmneziaWG: a full profile connects on the first tap, with
RIVET/Xray kept as fallbacks. Verified on a POCO X6 5G (Android 16): clean import of the
`Telefon KA` profile, `10.78.0.2` tunnel, server handshake, egress IP `81.177.142.37`, Wi-Fi ↔ LTE
switching without a drop, full `flutter test` — 1138 passed, 23 skipped.
[Details](docs/ANDROID-VALIDATION-20261117.md).

## Не выпущено — каскад бесплатный, OpenVPN/Cloak удалён / Unreleased — free cascade, OpenVPN/Cloak removed

RU: каскад больше не платный: `CascadeFeatureGate.enabled` всегда true, `CascadeSubscription`
по умолчанию `entitled: true`, плашки «Платная функция» в 13 каталогах заменены, `cascadeUnlocked`
включается по умолчанию, а экран каскада не требует активации. На главном экране появилась схема
подключённого каскада: устройство → bridge → exit, итог последней реальной SSH-проверки, отклик
и выходной IPv6; итог сохраняется в профиле (`cascadeHealthOk`, `cascadeHealthPingMs`,
`cascadeExitIpv6`, `cascadeCheckedAt`), тап открывает полный экран. Из клиента удалён транспорт
OpenVPN/Cloak: убран из каталога `protocols`, `nativeProtocols`, `universalProtocolIds`,
`restrictedNetworkProtocols`, расширенного импорта (`extendedProtocols`), лицензий и UI-имён;
профиль с контейнером `amnezia-openvpn-cloak` теперь отклоняется целиком, а не импортируется
частично. Формат капсулы выдачи намеренно не менялся: старые капсулы остаются читаемыми, новые
с этим транспортом не выпускаются.

EN: the cascade is no longer paid: `CascadeFeatureGate.enabled` is always true,
`CascadeSubscription` defaults to `entitled: true`, the paid-feature banners in 13 catalogues are
replaced, `cascadeUnlocked` defaults to enabled and the cascade screen needs no activation. The home
screen now shows the connected cascade scheme — device → bridge → exit, the result of the last real
SSH check, latency and egress IPv6 — persisted in the profile (`cascadeHealthOk`,
`cascadeHealthPingMs`, `cascadeExitIpv6`, `cascadeCheckedAt`); tapping opens the full screen.
OpenVPN/Cloak is removed from the client: dropped from `protocols`, `nativeProtocols`,
`universalProtocolIds`, `restrictedNetworkProtocols`, the extended importer (`extendedProtocols`),
licences and UI names; a profile with an `amnezia-openvpn-cloak` container is now rejected as a
whole instead of being partially imported. The issuance capsule format is deliberately unchanged:
old capsules stay readable, new ones are never issued with this transport.

## Не выпущено — изменённые исходники AWG в git

RU: чистый клон больше не требует «магии». `vendor/amneziawg-go` (fork `amnezia-vpn/amneziawg-go` v3.1.20260814 с XIO-патчем активации) и `vendor/amneziawg` (Android-мост с готовыми `jniLibs`) теперь обычные файлы в git — не сабмодули и не LFS. Сабмодуль отклонён: апстрим не содержит XIO-патча (`device/activation_endpoint.go`, `device/observation.go` и правки в `device/{device,peer,receive,noise-protocol}.go`), который обязателен для `protocol/rivet`, а `git archive` не включает содержимое сабмодулей и ломал бы архивы исходников. `.gitignore` правок не потребовал — этих путей там не было. `python3 tools/package-server.py --check` теперь упирается только в артефакты `vendor-server/*`, которые создаёт `tools/build-rivet.py`.

EN: a clean clone no longer needs magic. `vendor/amneziawg-go` (a fork of `amnezia-vpn/amneziawg-go` v3.1.20260814 with the XIO activation patch) and `vendor/amneziawg` (the Android bridge with prebuilt `jniLibs`) are now ordinary tracked files — no submodules, no LFS. The submodule variant was rejected: upstream has no XIO patch (`device/activation_endpoint.go`, `device/observation.go` and edits in `device/{device,peer,receive,noise-protocol}.go`) that `protocol/rivet` requires, and `git archive` omits submodule content, which would break source archives. `.gitignore` needed no change: neither path was ignored. `python3 tools/package-server.py --check` now only lacks the `vendor-server/*` artifacts produced by `tools/build-rivet.py`.

## Рецепт 28 — 2026-11-05, серверный архив пересобран из main

RU: рецепт 28: серверный архив собран после слияния `main` с MTProto-прокси Telegram (`mtg` 2.3.0, действие `mtproto` отдаёт готовую ссылку), выдачи IPv6-only профилей AmneziaWG (`ipv6Only`), статических AWG-пиров для сторонних устройств (`add-awg`), живой проверки каскада (`cascade_status`: маршрут плюс ping/TCP-проба с кешем), IPv4 для AWG-клиентов через NAT64 и IPv4 каскада через `tun0`, действия `catalog` для каталога «белых» SNI с недельным таймером, а также фиксов firewall (RELATED для ICMP, один дамп правил вместо `-C` на каждое правило), статистики на `restrictedNetwork` (нулевые счётчики вместо `KeyError`), sandbox-дропина (`ProtectSystem=full` + `ReadWritePaths`), `stats` с одним замером часов на проход и `wg syncconf` без `wg-quick`. `RECIPE` поднят до 28, `update.py` принимает 25, 26 и 27 как источники миграции, поэтому уже установленные 27-е хосты обновляются. Натив не пересобирался ради совместимости с AAR в приложении 0.24.2: канонический `tools/build-rivet.py` на Debian 13 с Go 1.27.3 даёт те же бинари (`rivet` `211369dc…`, `xraygateway` `976eac59…`, `cloak` `06dfbfd4…`, `amneziawg-go` `fc1a1f9f…`) и новый `sourceSha256` `cbd1f3cb…`; `rivet.aar` остаётся `cfc336c9…`. Манифест, архив (sha256 `ae9dfdca…`, 35 членов) и независимые копии (`xio-admin.py` байт-в-байт как `admin.py` в архиве, `mesh-pins.json`, `xio-server-update.py`) синхронизированы; рассинхрон прошлой поставки (`mesh-pins.json` `cf2bd08f…` при манифесте `ea7a3b5d…`, `xio-server-update.py` с `RECIPE = 26`) устранён. Живая установка на сервер в этом прогоне не выполнялась.
EN: recipe 28: the server archive is rebuilt from `main` after the merge of the Telegram MTProto proxy (`mtg` 2.3.0, the `mtproto` action returns a ready link), IPv6-only AmneziaWG profiles (`ipv6Only`), static AWG peers for third-party devices (`add-awg`), the live cascade check (`cascade_status`: route plus a cached ping/TCP probe), IPv4 for AWG clients through NAT64 and IPv4 for the cascade through `tun0`, the `catalog` action behind the white-SNI catalog and its weekly timer, plus fixes to the firewall (RELATED for ICMP, one rule dump instead of `-C` per rule), to statistics on `restrictedNetwork` (zero counters instead of `KeyError`), to the sandbox drop-in (`ProtectSystem=full` + `ReadWritePaths`), to `stats` (one clock sample per pass) and to `wg syncconf` without `wg-quick`. `RECIPE` is 28 and `update.py` accepts 25, 26 and 27 as migration sources, so hosts already on 27 upgrade. Natives are not rebuilt in order to stay compatible with the AAR shipped in app 0.24.2: the canonical `tools/build-rivet.py` on Debian 13 with Go 1.27.3 produces the same binaries (`rivet` `211369dc…`, `xraygateway` `976eac59…`, `cloak` `06dfbfd4…`, `amneziawg-go` `fc1a1f9f…`) and the new `sourceSha256` `cbd1f3cb…`; `rivet.aar` stays `cfc336c9…`. The manifest, the archive (sha256 `ae9dfdca…`, 35 members) and the standalone copies (`xio-admin.py` byte-identical to the `admin.py` member, `mesh-pins.json`, `xio-server-update.py`) are in sync; the drift of the previous payload (`mesh-pins.json` `cf2bd08f…` against manifest `ea7a3b5d…`, `xio-server-update.py` with `RECIPE = 26`) is fixed. A live install on a server was not performed in this run.
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