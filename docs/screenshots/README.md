# Скриншоты для README и документации

[Главная](../../README.ru.md) · [Возможности](../features.ru.md) · [Схемы](../landing/architecture.mmd) · [Home (EN)](../../README.md)

Здесь список кадров, которые нужны главной странице и разделам по платформам, и точные
инструкции, как их снять. **Сами скриншоты в этом каталоге пока не сняты** — таблица ниже
разметка, а не отчёт.

> ⚠️ Главное ограничение: Android-приложение ставит `FLAG_SECURE`. Системный `screencap`
> вернёт **чёрный кадр** — это защита, а не баг. Рабочий путь для Android — golden-кадры из
> widget-тестов (так сделаны `docs/images/settings-ru.png`, `connection-ru.png`,
> `about-ru.png`). Подробности в [разделе 5](#5-если-кадр-чёрный-android-и-flag_secure).

---

## 1. Соглашения

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

## 2. Что нужно снять

### Android · Full XIO (`app.xio.xio`)

| # | Экран | Что должно быть видно | Зачем на главной |
|---|---|---|---|
| A1 | Главная, подключено | статус «Туннель активен · DNS через туннель», растущие счётчики | первый экран, доказательство работы |
| A2 | Соединение → «Каскад: два сервера» | строка входа в каскад рядом с «Субклиенты» и «Проверка соединения» | показать точку входа |
| A3 | Экран «Каскад» | три станции, флаги, пинг, плашка «Платная функция» | главный кадр каскада |
| A4 | Экран «Каскад» после «Переподключить» | промежуточная стадия: жёлтая линия, «Устройство → Bridge · подключение» | показать состояния линии |
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

## 3. Подготовка телефона (Android)

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

## 4. Как открыть нужный экран

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

Путь для A4 — тот же экран, но нажать **«Переподключить»** и поймать кадр в первые
1,5 секунды: стадия `deviceToBridge` живёт 1800 мс, `bridgeToExit` — ещё 1600 мс.

Путь для C1 (Client): `am start` → на экране подключения кнопка **«Каскад: два сервера»**.
Путь для A5: **«+» → Настройка сервера** → прокрутить до галочки **«Включить каскад»**.

---

## 5. Если кадр чёрный (Android и `FLAG_SECURE`)

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

## 6. Windows 11

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

## 7. Ubuntu

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

## 8. Веб-панель сервера

```bash
sudo ./install-webui.sh 0.0.0.0:10443        # скрипт печатает URL с токеном
# в браузере: https://<server>:10443/?token=<токен>
```

Самоподписанный сертификат → браузер покажет предупреждение, это нормально. **Перед
публикацией вырежьте из адресной строки `?token=…`** и замажьте IP, если он не должен быть
публичным.

---

## 9. Заготовка таблицы

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

---

## 10. Что уже есть в репозитории

Эти кадры — не новые, они сняты раньше и уже используются в документации:

| Файл | Что на нём |
|---|---|
| `docs/images/2026-10-26-full-home.png` | Full XIO, главная |
| `docs/images/2026-10-26-full-settings.png` | Full XIO, настройки |
| `docs/images/2026-10-26-win-windows-home.png` | XIO Client для Windows |
| `docs/images/2026-10-26-win-windows-connecting.png` | XIO Client для Windows, подключение |
| `docs/images/2026-10-26-full-connection.png` | Full XIO, «Соединение» |
| `docs/images/client-0.22.4-dark.png`, `client-0.22.4-light.png` | XIO Client, тёмная и светлая темы |
| `docs/images/settings-ru.png`, `connection-ru.png`, `about-ru.png` | Android-экраны из widget-тестов |
| `docs/cascade/assets/cascade-screen.svg` | макет экрана «Каскад» (вектор, не скриншот) |

Пока новых кадров нет, главная страница использует именно их плюс векторные схемы из
`docs/landing/`. Так честнее, чем ставить в README «ожидаемый» кадр.
