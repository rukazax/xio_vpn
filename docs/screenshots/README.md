# Скриншоты для README и документации

[Главная](../../README.ru.md) · [Возможности](../features.ru.md) · [Схемы](../landing/architecture.mmd) · [Home (EN)](../../README.md)

Десять кадров Android-интерфейса уже сняты и лежат рядом с этим файлом — их рисует сам
Flutter в widget-тесте (раздел 1). Остальные кадры (Windows, Ubuntu, телефон, веб-панель,
терминал) ещё нужно снять: для них ниже точные инструкции и таблица статусов, а не выдумка.

> ⚠️ Главное ограничение: Android-приложение ставит `FLAG_SECURE`. Системный `screencap`
> вернёт **чёрный кадр** — это защита, а не баг. Рабочий путь для Android — golden-кадры из
> widget-тестов (так сделаны `docs/images/settings-ru.png`, `connection-ru.png`,
> `about-ru.png` и все кадры раздела 1). Подробности в
> [разделе 6](#6-если-кадр-чёрный-android-и-flag_secure).

---

## 1. Снятые кадры (golden-рендер, PNG)

Все десять кадров получены `flutter test` на Debian 13, `Flutter 3.47.7`, тема тёмная, язык
`ru`. Кадр рисует Flutter, а не система, поэтому `FLAG_SECURE` ему не мешает. Файлы —
настоящие PNG, не SVG и не макеты.

| Файл | Что на нём | Размер | Как воспроизвести |
|---|---|---|---|
| `main-idle.png` | Главная: «Отключено», круглая кнопка «Подключиться», выбранный сервер «🇷🇺 Основной сервер», «Автоматически · Xray / REALITY», счётчики 0 B | 1080×2400 | тест `main screen: idle, server chosen` |
| `connection-tab.png` | Вкладка «Соединение»: «Вставить ключ или конфигурацию», «Файл с настройками подключения», «VPN на своём сервере», «Каскад: два сервера» (`IPv4 → bridge → IPv6 exit · по подписке`), «Добавить пользователя» | 1080×2400 | тест `connection tab: key, own server, cascade, user` |
| `cascade-configured.png` | Экран «Каскад» с настроенными адресами: Устройство → Bridge `81.177.142.37` → Exit `2a0c:b641:1a0:800::2a2`, «Готов к подключению», «Отклик —», «Выходной IPv6 —», кнопка «Проверить каскад», плашка подписки «XIO Cascade» | 1080×2400 | тест `cascade screen: configured bridge and IPv6 exit` |
| `cascade-health.png` | Тот же экран после «Проверить каскад», когда проверка вернула `ok`: зелёные линии и станции, «Защищённый туннель только IPv6 · проверено», «Отклик 214 мс», «Выходной IPv6 2a0c:b641:1a0:800::2a2», «Обновлено 23:40:00» | 1080×2400 | тест `cascade health: result of «Проверить каскад»` |
| `cascade-servers-dialog.png` | Диалог «Серверы каскада»: два поля (Bridge IPv4/домен, Exit только IPv6) с заполненными адресами и готовая команда установки `--role bridge --exit-host 2a0c:b641:1a0:800::2a2` | 1080×2400 | тест `cascade servers dialog: two fields and the install command` |
| `settings.png` | Настройки: Серверы, Соединение, Приложение, Пользователи, Поддержать XIO, О XIO | 824×1830 (412×915 @2×) | тест `settings: list, then the application/locale screen` |
| `settings-locales.png` | «Приложение» целиком: язык «Русский · ru», «Проверить обновления», три переключателя, «Оформление» | 824×1830 (412×915 @2×) | тот же тест, второй кадр |
| `settings-dns.png` | «DNS-резолвер»: пояснение, четыре готовых набора (AdGuard DNS (IPv6), Quad9, Cloudflare, Google Public DNS) с отмеченным Cloudflare, пункт «Свои» и кнопка «Сохранить» | 1080×2400 | тест `dns resolver: presets, the saved pair and the custom fields` |
| `settings-mtproto.png` | «Telegram-прокси (MTProto)»: четыре шага включения прокси в Telegram, поле «Ссылка прокси» с `tg://proxy?…`, подпись «Сервер: proxy.xio.fr:443», кнопки «Сохранить / Скопировать / Открыть в Telegram / Вставить / Очистить» и строка «Прокси настроен» | 1080×2400 | тест `mtproto proxy: instruction, saved link and status` |
| `settings-behaviour.png` | Три переключателя экрана «Приложение»: «Автозапуск при загрузке устройства», «Автоподключение после запуска» (вкл.), «Разрешить скриншоты» (вкл.) с подписями-пояснениями | 1080×2400 | тест `application settings: autostart, auto-connect, screenshots` |

Команда прогона (из каталога `app/`):

```sh
flutter pub get
XIO_CAPTURE_IMAGES=1 flutter test test/screenshots
```

Без `XIO_CAPTURE_IMAGES=1` тест всё равно рендерит все экраны и проверяет их, но **ничего не
пишет**: прогон тестов не меняет версионируемые файлы. С `=1` PNG-файлы перезаписываются в
`docs/screenshots/`.

> Предварительно должны быть собраны серверные ассеты: `pubspec.yaml` тянет в asset-bundle
> `assets/xio-server.tar.gz` и `assets/xio_vici/`, а это сборные артефакты
> (`python3 tools/package-server.py`, см. [сборку](../ru/build.md)). В свежем клоне без них
> `flutter pub get` и `flutter test` падают на сборке asset-bundle — это не ошибка теста.

Что важно знать про эти кадры (честные ограничения):

- размер задаёт тест: телефон — `tester.view.physicalSize = 1080×2400`, `devicePixelRatio = 3`
  (логический 360×800), кадр `settings*.png` — 412×915 логических при `pixelRatio = 2×`;
- плашка подписки на `cascade-configured.png` — состояние «подписка активна»
  (`CascadeSubscription(entitled: true, planLabel: 'XIO Cascade')`). Сама подписка пока
  заглушка: `CascadeFeatureGate.enabled == false`, поэтому кнопка «Активировать» в кадре
  ничего не включает;
- кнопка «Проверить каскад» в этих кадрах настоящая: она заблокирована на время запроса и
  опрашивает bridge по SSH (`CascadeSshProbe`, тайм-аут 15 с). В widget-тесте SSH заменить
  нечем, поэтому `cascade-health.png` подставляет в `healthProbe` заранее известный
  `CascadeHealth(verdict: ok, latencyMs: 214, egressIpv6: 2a0c:b641:1a0:800::2a2)`: кадр
  документирует **состояние экрана после успешной проверки**, а не результат живого сервера.
  Сам экран при этом ничего не выдумывает — без ответа probe оставляет «—»;
- `cascade-configured.png` до нажатия показывает «Отклик —» и «Выходной IPv6 —», а время в
  строке «Обновлено» — момент открытия экрана, не результат проверки;
- шрифты как в приложении: `X1oSans`, `X1oCJK` (из него же берётся стрелка `→`) и
  `MaterialIcons` входят в `app/assets`. Флаг страны (🇷🇺) и текст команды установки в
  моноширинном начертании берутся из системных `NotoColorEmoji` и `monospace` — на хосте без
  них на месте этих глифов будут пустые прямоугольники, а геометрия кадра не изменится;
- тест сам проверяет результат: PNG-сигнатуру, ожидаемый размер в пикселях и число разных
  цветов (чтобы «чёрный кадр» не мог пройти молча);
- `settings-behaviour.png` снят на Linux-хосте теста, а поведение «Автозапуска» в коде зависит от
  `Platform.isAndroid`. Поэтому в кадре переключатель «Автозапуск при загрузке устройства»
  неактивен, а его подпись — не-андроидная ветка («Доступно в сборке для Android…»). На телефоне
  переключатель активен; остальные две строки («Автоподключение», «Разрешить скриншоты») рисуются
  одинаково на любой платформе. Это ограничение хоста, а не состояние приложения.

Примеры самих тестов — `app/test/screenshots/capture_screens_test.dart`, общий помощник
захвата — `app/test/support/screenshots.dart`.

---

## 2. Соглашения

| Что | Как |
|---|---|
| Имя файла | `<платформа>-<экран>-<тема>-<версия>.png`, например `android-home-dark-0.24.1.png` |
| Формат | PNG, без потерь, ширина 1080 px для телефона, 1440 px для десктопа |
| Тема | `dark` и `light` парой; в README показываем обе |
| Язык | `ru` и `en` парой, кадр снимается один раз на язык |
| Приватность | IP сервера, домены, имена пользователей и токены — замазать до публикации |
| Куда кладём | `docs/screenshots/<платформа>/`, в README — ссылка относительная |

Правило приватности важнее красоты: один незамазанный `token=` в кадре веб-панели —
это опубликованный доступ, а не скриншот.

---

## 3. Что нужно снять

### Android · Full XIO (`app.xio.xio`)

| # | Экран | Что должно быть видно | Зачем на главной |
|---|---|---|---|
| A1 | Главная, подключено | статус «Туннель активен · DNS через туннель», растущие счётчики | первый экран, доказательство работы |
| A2 | Соединение → «Каскад: два сервера» | строка входа в каскад рядом с «Субклиенты» и «Проверка соединения» | показать точку входа |
| A3 | Экран «Каскад» | три станции, флаги, «Отклик —», кнопка «Проверить каскад», плашка «Платная функция» | главный кадр каскада |
| A4 | Экран «Каскад» после «Проверить каскад» | зелёные станции, «Отклик 214 мс», реальный выходной IPv6 и время проверки | показать результат реальной проверки |
| A5 | Форма установки сервера | галочка «Включить каскад (по подписке)» | установка из приложения |
| A6 | Пользователи | карточка с ролью, online, трафиком за месяц | управление сервером |
| A7 | Настройки → Соединение | «Протоколы», приоритет, тайм-аут, «Проверять доступность сайта» | раздельное туннелирование и протоколы |
| A8 | О XIO | лицензия, GitHub, «Поделиться приложением» | доверие и лицензия |

### Android · XIO Client (`app.xio.client`)

| # | Экран | Что должно быть видно | Зачем |
|---|---|---|---|
| C1 | Экран подключения | кнопка «Каскад: два сервера» рядом с «Субклиенты»/«Проверка соединения» | каскад в клиентской сборке |
| C2 | Список профилей | профиль `xio://`, выбранный транспорт, кнопка «Подключить» | «просто подключиться» |
| C3 | Подключено | тот же экран после успешной проверки | подтверждение |

### Windows 11 · Full XIO и Client

| # | Экран | Что должно быть видно |
|---|---|---|
| W1 | Full XIO, главная | карточка сервера, состояние юнитов |
| W2 | Full XIO, профиль сервера | адрес, SSH, кнопки обслуживания |
| W3 | XIO Client, главная | выбор профиля и «Подключить» |
| W4 | XIO Client, подключение | счётчики и статус проверки |
| W5 | Предупреждение SmartScreen | честный кадр: сборка не подписана сертификатом издателя |

### Ubuntu

| # | Экран | Что должно быть видно |
|---|---|---|
| U1 | Окно Full XIO | главная, тёмная тема |
| U2 | Окно Full XIO | настройки соединения |

> GUI Ubuntu в 0.24.0 живьём не перепроверялся (в 0.23.0 окно не создавалось). Кадры U1–U2
> снимаем только после реального запуска, иначе в таблице остаётся `NOT_EXECUTED`.

### Сервер Linux

| # | Кадр | Что должно быть видно |
|---|---|---|
| S1 | Веб-панель, состояние | службы, версия, роль каскада, пользователи |
| S2 | Веб-панель, пользователи | добавление и отзыв, без секретов в кадре |
| S3 | `systemctl status xio-managed-awg` | `active (running)` |
| S4 | `cascade-healthcheck.sh --role both` | JSON `{"ok": true}` |

S3–S4 — это кадры терминала, а не интерфейса: они хорошо смотрятся в разделе «что проверено».

---

## 4. Подготовка телефона (Android)

Телефон: POCO X6 5G, Android 16, serial `909f194a`. adb:
`C:\Users\er-ka\.dsh\bin\platform-tools\adb.exe` (каталог уже добавлен в PATH пользователя).

```powershell
# 1. Устройство на связи и авторизовано
adb devices -l
# ожидаем: 909f194a   device   product:garnet ...

# 2. Какая версия приложения стоит
adb -s 909f194a shell dumpsys package app.xio.xio | Select-String versionName, versionCode
adb -s 909f194a shell dumpsys package app.xio.client | Select-String versionName, versionCode

# 3. Экран, плотность и ориентация — чтобы кадры были одинаковыми
adb -s 909f194a shell wm size
adb -s 909f194a shell wm density
adb -s 909f194a shell settings get system user_rotation

# 4. Разбудить, снять блокировку, выключить анимации (иначе ловим промежуточный кадр)
adb -s 909f194a shell input keyevent KEYCODE_WAKEUP
adb -s 909f194a shell input swipe 540 2100 540 600 200
adb -s 909f194a shell settings put global window_animation_scale 0
adb -s 909f194a shell settings put global transition_animation_scale 0
adb -s 909f194a shell settings put global animator_duration_scale 0

# 5. Тёмная и светлая тема — переключаем в самой системе, приложение следует за ней
adb -s 909f194a shell cmd uimode night yes     # тёмная
adb -s 909f194a shell cmd uimode night no      # светлая
```

После съёмки верните анимации: `adb shell settings put global window_animation_scale 1`
(и две остальные так же).

---

## 5. Как открыть нужный экран

У приложения нет deep-link, кроме каскадного маршрута `CascadeScreen.routeName = /cascade`
(внутренний маршрут Flutter, снаружи недоступен). Поэтому: запускаем activity, дальше идём по
интерфейсу.

```powershell
# Full XIO
adb -s 909f194a shell am start -n app.xio.xio/.MainActivity
# XIO Client
adb -s 909f194a shell am start -n app.xio.client/.MainActivity
```

Дальше — навигация по координатам. Чтобы не угадывать, снимите разметку и найдите элемент:

```powershell
adb -s 909f194a shell uiautomator dump /sdcard/ui.xml
adb -s 909f194a pull /sdcard/ui.xml
# в файле ищем text="Каскад: два сервера" и берём bounds="[x1,y1][x2,y2]"
```

Центр берётся как `((x1+x2)/2, (y1+y2)/2)`, нажатие:

```powershell
adb -s 909f194a shell input tap 610 1420
```

Путь для A3 (экран «Каскад», Full):

1. `am start` → вкладка **«Соединение»**;
2. строка **«Каскад: два сервера»**;
3. дать экрану дорисоваться 2 секунды (`Start-Sleep -Seconds 2`);
4. `screencap` (раздел 5).

Путь для A4 — тот же экран, но нажать **«Проверить каскад»** и дождаться ответа (до 15 с):
пока идёт SSH-запрос, кнопка показывает «Проверка…» и заблокирована; после ответа экран
показывает отклик, выходной IPv6 и причину отказа, если проверка не прошла. Промежуточные
жёлтые стадии больше не рисуются таймером — они появляются только по настоящему ответу.

Путь для C1 (Client): `am start` → на экране подключения кнопка **«Каскад: два сервера»**.
Путь для A5: **«+» → Настройка сервера** → прокрутить до галочки **«Включить каскад»**.

---

## 6. Если кадр чёрный (Android и `FLAG_SECURE`)

```powershell
# Основной способ: файл на устройстве, потом pull — не ломается на бинарных данных
adb -s 909f194a shell screencap -p /sdcard/xio-shot.png
adb -s 909f194a pull /sdcard/xio-shot.png .\xio-shot.png
adb -s 909f194a shell rm /sdcard/xio-shot.png

# Быстрый способ (PowerShell 7+); в PowerShell 5.1 ">" испортит PNG
adb -s 909f194a exec-out screencap -p > .\xio-shot.png
```

Проверка «чёрный или нет» без открытия файла:

```powershell
python -c "from PIL import Image; im=Image.open(r'.\xio-shot.png').convert('L'); print('max', im.getextrema()[1])"
```

`max 0` — кадр полностью чёрный, сработал `FLAG_SECURE`. Дальше два honest-варианта:

1. **Golden из widget-теста (рекомендуется).** Так получены уже опубликованные кадры
   `docs/images/*-ru.png` и `*-en.png`: кадр рисует Flutter, а не система, поэтому защита
   экрана не мешает. В самом приложении это `flutter test` с `matchesGoldenFile`.
2. **Отдельная отладочная сборка без `FLAG_SECURE`.** Это изменение кода приложения, а не
   документации: в задаче «только docs/README» его делать нельзя. Если понадобится — отдельная
   задача и отдельный APK, ни в коем случае не публикуемая сборка.

`adb shell screenrecord` даёт тот же чёрный кадр: защита работает на уровне поверхности.

---

## 7. Windows 11

```powershell
# Полностью распаковать ZIP, запустить приложение
Start-Process .\XIO.exe
```

Снимать проще всего инструментом computer-use этого рабочего места: `list_windows` → нужный
`pid` → `get_window_state` (он отдаёт PNG окна). Альтернатива без инструментов:
`Win+Shift+S` → «Окно» → сохранить в `docs/screenshots/windows/`.

SmartScreen (W5) ловится сразу после первого запуска: «Windows protected your PC» →
«More info». Кадр нужен именно с предупреждением — это честно.

---

## 8. Ubuntu

```bash
# X11
import -window root ~/xio-ubuntu-home.png
# Wayland (GNOME)
gnome-screenshot -f ~/xio-ubuntu-home.png
# Wayland (wlroots)
grim ~/xio-ubuntu-home.png
```

Перед съёмкой: `sudo apt install ./XIO-Full-0.24.0-ubuntu-amd64.deb`, запуск из меню.
Если окно не появляется — это известное ограничение, кадр не снимаем, ставим `NOT_EXECUTED`.

---

## 9. Веб-панель сервера

```bash
sudo ./install-webui.sh 0.0.0.0:10443        # скрипт печатает URL с токеном
# в браузере: https://<server>:10443/?token=<токен>
```

Самоподписанный сертификат → браузер покажет предупреждение, это нормально. **Перед
публикацией вырежьте из адресной строки `?token=…`** и замажьте IP, если он не должен быть
публичным.

---

## 10. Заготовка таблицы

Заполняется по мере съёмки. `NOT_EXECUTED` — не «забыли», а «не снимали и не будем делать вид».

| ID | Файл | Платформа | Тема | Язык | Устройство / версия | Статус |
|---|---|---|---|---|---|---|
| A1 | `android/android-home-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A1 | `android/android-home-light-0.24.1.png` | Android Full | light | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A2 | `android/android-connection-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A3 | `android/android-cascade-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A4 | `android/android-cascade-connecting-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A5 | `android/android-server-setup-cascade-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A6 | `android/android-users-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A7 | `android/android-settings-connection-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| A8 | `android/android-about-dark-0.24.1.png` | Android Full | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| C1 | `android/client-connect-dark-0.24.1.png` | Android Client | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| C2 | `android/client-profiles-dark-0.24.1.png` | Android Client | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| C3 | `android/client-connected-dark-0.24.1.png` | Android Client | dark | ru | POCO X6 5G / 0.24.1+5018 | NOT_EXECUTED |
| W1 | `windows/full-home-dark-0.24.0.png` | Windows 11 x64 | dark | ru | ПК, 0.24.0 | NOT_EXECUTED |
| W2 | `windows/full-profile-dark-0.24.0.png` | Windows 11 x64 | dark | ru | ПК, 0.24.0 | NOT_EXECUTED |
| W3 | `windows/client-home-dark-0.23.1.png` | Windows 11 x64 | dark | ru | ПК, 0.23.1 | NOT_EXECUTED |
| W4 | `windows/client-connected-dark-0.23.1.png` | Windows 11 x64 | dark | ru | ПК, 0.23.1 | NOT_EXECUTED |
| W5 | `windows/smartscreen-0.24.0.png` | Windows 11 x64 | — | ru | ПК, 0.24.0 | NOT_EXECUTED |
| U1 | `ubuntu/full-home-dark-0.24.0.png` | Ubuntu 22.04+ | dark | ru | нужен запуск GUI | NOT_EXECUTED |
| U2 | `ubuntu/full-settings-dark-0.24.0.png` | Ubuntu 22.04+ | dark | ru | нужен запуск GUI | NOT_EXECUTED |
| S1 | `server/webui-state-0.24.0.png` | Debian 13 | dark | ru | сервер стенда | NOT_EXECUTED |
| S2 | `server/webui-users-0.24.0.png` | Debian 13 | dark | ru | сервер стенда | NOT_EXECUTED |
| S3 | `server/systemctl-xio-managed-awg.png` | Debian 13 | — | ru | сервер стенда | NOT_EXECUTED |
| S4 | `server/cascade-healthcheck.png` | Debian 13 | — | ru | живая пара bridge+exit | NOT_EXECUTED |

Статусы: `DONE` — снято и проверено глазами; `BLOCKED` — нельзя снять сейчас (и почему);
`NOT_EXECUTED` — не начинали.

Часть пунктов уже закрыта golden-кадрами из раздела 1 — не телефоном, а рендером тех же
экранов, поэтому строки ниже остаются `NOT_EXECUTED` только для съёмки на устройстве:

| Пункт | Закрывает кадр | Чем отличается от съёмки на телефоне |
|---|---|---|
| A1 (главная, «Отключено») | `main-idle.png` | нет системной строки состояния, тёмная тема принудительная |
| A2 (вкладка «Соединение») | `connection-tab.png` | то же |
| A3 (экран «Каскад», настроенные адреса) | `cascade-configured.png` | подписка показана активной (заглушка `enabled == false`) |
| A4 (экран «Каскад» после проверки) | `cascade-health.png` | probe подставлен тестом: кадр показывает состояние экрана после `ok`, а не живой SSH-ответ сервера |
| A5 (форма установки) | `cascade-servers-dialog.png` | это диалог адресов, а не галочка «Включить каскад» |
| A7 (настройки → «Приложение») | `settings.png`, `settings-locales.png` | «Оформление» без выбора темы: приложение следует системной |
| A7 (Соединение → «DNS-резолвер») | `settings-dns.png` | выбор набора без системной строки состояния |
| A7 (Настройки → «Telegram-прокси (MTProto)») | `settings-mtproto.png` | экран настроек без системной строки состояния |
| A7 (Приложение → автозапуск/автоподключение/скриншоты) | `settings-behaviour.png` | на Linux-хосте «Автозапуск» неактивен и с не-андроидной подписью |

---

## 11. Что уже есть в репозитории

Свежие кадры Android-интерфейса (раздел 1) — `docs/screenshots/*.png`. Остальное снято
раньше и уже используется в документации:

| Файл | Что на нём |
|---|---|
| `docs/screenshots/main-idle.png` | Android Full, главная: «Отключено», выбор сервера (golden) |
| `docs/screenshots/connection-tab.png` | Android Full, вкладка «Соединение» (golden) |
| `docs/screenshots/cascade-configured.png` | Android Full, «Каскад» с настроенными адресами (golden) |
| `docs/screenshots/cascade-health.png` | Android Full, «Каскад» после успешной «Проверить каскад» (golden) |
| `docs/screenshots/cascade-servers-dialog.png` | Диалог «Серверы каскада» и команда установки (golden) |
| `docs/screenshots/settings.png`, `settings-locales.png` | Android Full, настройки и «Приложение» (golden) |
| `docs/screenshots/settings-dns.png` | Android Full, «DNS-резолвер»: наборы и «Свои» (golden) |
| `docs/screenshots/settings-mtproto.png` | Android Full, «Telegram-прокси (MTProto)» с сохранённой ссылкой (golden) |
| `docs/screenshots/settings-behaviour.png` | Android Full, три переключателя «Приложения» (golden) |
| `docs/images/2026-10-26-full-home.png` | Full XIO, главная |
| `docs/images/2026-10-26-full-settings.png` | Full XIO, настройки |
| `docs/images/2026-10-26-win-windows-home.png` | XIO Client для Windows |
| `docs/images/2026-10-26-win-windows-connecting.png` | XIO Client для Windows, подключение |
| `docs/images/2026-10-26-full-connection.png` | Full XIO, «Соединение» |
| `docs/images/client-0.22.4-dark.png`, `client-0.22.4-light.png` | XIO Client, тёмная и светлая темы |
| `docs/images/settings-ru.png`, `connection-ru.png`, `about-ru.png` | Android-экраны из widget-тестов |
| `docs/cascade/assets/cascade-screen.svg` | макет экрана «Каскад» (вектор, не скриншот) |

Кадров Windows, Ubuntu, телефона и серверной веб-панели по-прежнему нет: вместо них в
документации стоят более старые снимки и векторные схемы из `docs/landing/`. Так честнее,
чем ставить в README «ожидаемый» кадр.
