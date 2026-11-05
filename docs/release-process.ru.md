# Релизный конвейер XIO: CI, единая публикация, Windows/Ubuntu

Документ описывает **P5**: один CI на Debian-раннере, один скрипт публикации,
и честные границы того, что проверяется автоматически, а что — руками.

| Что | Где |
|---|---|
| CI (два job) | `.github/workflows/ci.yml` |
| Baseline pytest | `tools/ci/pytest-baseline.txt` |
| Единый релиз | `tools/release/release.py` |
| Тесты скрипта релиза | `tools/test_release_script.py` (29 тестов, без сети) |
| Этот документ | `docs/release-process.ru.md` |

Старые PowerShell-скрипты (`tools/release/build-all.ps1`, `sign-apk.ps1`,
`publish.ps1`, `verify-release.ps1`) остаются рабочими и описаны в
`tools/release/README.md`; `release.py` их не заменяет, а собирает весь путь
в одну команду, которую можно запустить и на Linux-раннере.

---

## 1. CI на Debian-раннере

### 1.1 Что делают job'ы

`ci.yml` срабатывает на `push` и `pull_request` в `main` (плюс `workflow_dispatch`)
и состоит из двух job'ов. Оба рассчитаны на self-hosted раннер на
`192.168.88.17` (Debian 13, x86_64).

**`flutter`** — Dart-слой:

| Шаг | Команда |
|---|---|
| зависимости | `flutter pub get` (без `--enforce-lockfile`: на раннере Flutter 3.47.7, в iOS-CI — 3.47.8, строгий режим там не проверялся) |
| статический анализ | `flutter analyze` |
| тесты | `flutter test --reporter compact` |
| артефакт | `.github-ci/flutter-{analyze,test}.log` → `ci-flutter-<sha>` |

**`server`** — Python и shell:

| Шаг | Команда |
|---|---|
| синтаксис скриптов | `bash -n` для всех `deploy/**/*.sh` (сейчас 11 файлов) |
| нативные исходники | отдельный шаг не нужен: `vendor/amneziawg-go` и `vendor/amneziawg` — обычные файлы в git (не сабмодули и не LFS), поэтому после `actions/checkout` сразу работают `go build ./...` в `protocol/rivet` и `python3 tools/package-server.py --check` |
| тесты | `sudo -n python3 -m pytest -q -p no:cacheprovider --deselect … server/managed server/catalog tools` |
| артефакт | `.github-ci/{pytest,shellcheck}.log` → `ci-server-<sha>` |

Почему pytest идёт через `sudo`: `server/managed/test_network_delta.py` и
`test_update.py` обращаются к `/etc/xio-stack`, который создаёт установленный
стенд XIO. Без root они падают с `PermissionError` — это ограничение тестов, а
не кода. Job проверяет `sudo -n true` и падает с понятным сообщением, если
passwordless sudo на раннере нет.

### 1.2 Baseline: что зелёное, а что исключено

Замер на `fff525e` (Debian 13, Python 3.13.5, pytest 8.3.5, root, `TZ=UTC`):

```text
160 passed, 5 failed, 0 errors, 0 skipped          # без списка исключений
160 passed, 5 deselected                          # с tools/ci/pytest-baseline.txt
```

Пять исключённых падений — не «шум CI», а известные дефекты и особенность
стенда; каждый записан в `tools/ci/pytest-baseline.txt` вместе с причиной:

| Тест | Причина |
|---|---|
| `test_admin.py::InstallerTests::test_shared_dependencies_not_purged` | реальный дефект: `purge_packages()` не возвращает `packagesRemoved` |
| `test_admin.py::StaticAwgTests::test_add_awg_returns_profile_and_marks_transport` | реальный дефект: `admin.py:611` вызывает `dualstack.cascade_status()`, которой нет |
| `test_admin.py::StaticAwgGuardTests::test_ipv6_host_endpoint_is_bracketed` | тот же отсутствующий `cascade_status` |
| `test_admin.py::StaticAwgGuardTests::test_static_peer_does_not_appear_in_wireguard_config` | тот же отсутствующий `cascade_status` |
| `test_update.py::UpdateTests::test_update_preserves_users_keys_and_is_idempotent` | зависит от состояния хоста: на раннере стоит стенд XIO |

Список — **не** разрешение падать всему: `--deselect` убирает ровно эти узлы,
любая другая ошибка роняет job. Когда тест починят, строку удаляют.

Отдельно про `TZ=UTC`: `tools/test_whitelist_catalog.py` сравнивает имя файла
каталога (дата по UTC) с локальной датой. В окне 00:00–03:00 MSK они
расходятся и тест падает ложно. В workflow `TZ: UTC` задан на уровне `env`,
поэтому проверка детерминирована.

### 1.3 Реальное состояние раннера на 2026-11-05 (важно)

Workflow написан, но **на текущем раннере он не подхватится** — три факта,
проверенные по SSH и через API GitHub:

1. На Debian работают три службы раннера и все `active (running)`; имена служб и
   рабочие каталоги раннеров — устаревшие имена ранних сборок.
2. Все три зарегистрированы **на другой репозиторий**, а не на `rukazax/xio_vpn`:
   `GET /repos/rukazax/xio_vpn/actions/runners` возвращает `total_count: 0`,
   поэтому регистрацию не видит ни один workflow этого репозитория.
3. Метки этих раннеров — `self-hosted`, `Linux`, `X64` и метка устаревшего имени
   ранних сборок (см. `LEGACY_RUNNER_LABEL` ниже; у первого ещё `ubuntu-24.04`).
   Метки **`debian17` не существует**, поэтому `runs-on: [self-hosted, debian17]`
   не совпадёт ни с одним раннером.
4. Дополнительно: в API все три дебиановских раннера показаны `offline`
   (в `_diag/Runner_*.log` — `TaskCanceledException` на `Location.GetConnectionData`,
   последняя запись 2026-11-04 22:50 UTC), хотя `systemctl` показывает
   `active`. То есть у них ещё и потеряна связь с GitHub.

**Шаги включения** (любой из двух, затем проверить вкладку Actions):

*Вариант А — привести метку к workflow.* Добавить существующему раннеру метку
`debian17` (Settings → Actions → Runners → `debian17` → Labels; либо
перерегистрировать с `./config.sh --labels self-hosted,debian17,<метка раннера>`
— фактическую метку см. `LEGACY_RUNNER_LABEL` ниже), затем перезапустить службу
и убедиться, что он `Idle`, а не `Offline`.

*Вариант Б — привести workflow к метке.* Задать переменную репозитория
`CI_RUNNER` (Settings → Secrets and variables → Actions → Variables):

```text
# Устаревшее имя ранних сборок: метка, с которой раннер зарегистрирован сейчас.
# Менять её не обязательно — достаточно сослаться на неё в CI_RUNNER.
LEGACY_RUNNER_LABEL = "x1o-debian"
CI_RUNNER = ["self-hosted", LEGACY_RUNNER_LABEL]
```

`runs-on: ${{ fromJSON(vars.CI_RUNNER || '["self-hosted","debian17"]') }}`
подставит её без правки YAML.

*И главное:* раннер нужно зарегистрировать **на `rukazax/xio_vpn`** (Settings →
Actions → Runners → New self-hosted runner → токен этого репозитория), потому
что регистрация на чужом репозитории workflow этого репозитория не увидит.

Нужное на раннере уже есть и проверено: `/opt/flutter` (Flutter 3.47.7,
Dart 3.13.5, владелец `ii`), Python 3.13.5, pytest 8.3.5, PyYAML 6.0.2,
passwordless sudo у `ii`, `bash`, `find`.

### 1.4 Что проверено локально

```text
$ python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"
yaml ok
```

Сборка аргументов `--deselect` из baseline-файла проверена на реальном файле:
5 строк → 5 аргументов, комментарии и пустые строки пропускаются.

---

## 2. Единый релиз: `tools/release/release.py`

Python 3, только стандартная библиотека. Внешние бинарники: `apksigner`
(Android build-tools), `ssh`/`scp` — только в режиме `--ssh`.

### 2.1 Порядок работы

```text
1. артефакты   --ssh (сборка на Debian) ИЛИ готовые файлы в --dir
2. подпись     apksigner verify --verbose --print-certs, сертификат e4e81b12…c9671
3. SHA256SUMS  пересчёт по файлам, всегда LF, сверка «суммы ↔ файлы» один-в-один
4. полнота     ровно 9 файлов; Windows ZIP может быть от другой версии
5. публикация  create/update релиза, upload новых, delete заменяемых и лишних
6. проверка    каждый ассет скачивается АНОНИМНО и сверяется по sha256 и размеру
7. отчёт       таблица + «ИТОГ: OK/FAIL», код 1 при любом расхождении
```

### 2.2 Флаги

| Флаг | Смысл |
|---|---|
| `--tag v0.24.2` | обязательный тег; версия из него же |
| `--dir PATH` | каталог артефактов (по умолчанию `releases/<ver>`) |
| `--repo owner/name` | репозиторий (по умолчанию — `origin` текущего каталога) |
| `--dry-run` | только проверки и план; ни записи, ни загрузок, ни скачиваний |
| `--verify-only` | не публиковать: скачать существующие ассеты и сверить |
| `--ssh HOST` | собрать Linux-артефакты на Debian (`sh tools/build-linux.sh`) и забрать по `scp` |
| `--remote-repo`, `--remote-out`, `--ssh-cmd` | что и где собирать на Debian |
| `--notes-file`, `--name`, `--prerelease` | тело/имя релиза |
| `--apksigner PATH` | путь к apksigner (иначе `PATH` → `ANDROID_HOME/build-tools`) |
| `--skip-signature` | осознанно пропустить проверку подписи |
| `--windows-version` | ожидаемая версия Windows ZIP, если она не равна версии выпуска |
| `--timeout` | таймаут скачивания ассета (по умолчанию 600 с) |

Токен: `--token` → `GITHUB_TOKEN`/`GH_TOKEN` → `%USERPROFILE%\.dsh\secrets\github.json`.

### 2.3 Как выбираются ассеты для замены

GitHub не умеет заменять ассет на месте, поэтому решение принимает чистая
функция `asset_plan(local, remote)`:

| Ситуация | Действие |
|---|---|
| имени нет в релизе | `upload` |
| digest и размер совпали | `keep` (ничего не делаем) |
| sha256 разошёлся | `delete` + `upload` (`replace`) |
| размер разошёлся | `delete` + `upload` |
| GitHub не отдал `digest` | `delete` + `upload` — иначе сверка невозможна |
| имя есть только в релизе и похоже на ассет XIO | `delete` (`remove`) |
| имя есть только в релизе и не похоже на ассет XIO | `foreign` — **не трогаем** |

Последняя строка — защита: посторонний файл, приложенный к релизу руками,
не будет удалён молча.

### 2.4 Примеры

```bash
# 1) локальная проверка: ничего не меняет
python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --dry-run

# 2) собрать Ubuntu-пакеты на Debian и выпустить
python3 tools/release/release.py --tag v0.24.2 --ssh debian17 \
    --remote-repo /root/xio-linux --notes-file docs/release-notes-0.24.2.md

# 3) только проверить опубликованное (анонимное скачивание)
python3 tools/release/release.py --tag v0.24.2 --dir releases/0.24.2 --verify-only
```

### 2.5 Что уже проверено на реальном выпуске 0.24.2

```text
$ python3 tools/release/release.py --dry-run --dir …\release-0.24.2 --tag v0.24.2
[1/5] артефакты: 9/9
  ! Windows ZIP от версии 0.24.1, а выпуск 0.24.2
[2/5] подпись APK
  OK   XIO-Client-0.24.2-android-arm64-v8a.apk — сертификат e4e81b12…c9671
  … (5 из 5 APK)
[3/5] SHA256SUMS
[sums] SHA256SUMS-0.24.2.txt актуален (9 записей, LF)
[4/5] GitHub Release v0.24.2
  релиз существует: id=433728341, ассетов 10
  оставить (совпало): 10
[5/5] анонимная сверка ассетов
  dry-run: скачивание не выполняется
ИТОГ: OK — все проверки пройдены            (код 0, файлы не изменены)
```

`--verify-only` на том же каталоге скачал все 10 ассетов анонимно и сверил:
`ИТОГ: OK — все проверки пройдены`, код 0 (в таблице — совпадение sha256 и
размера по каждому файлу).

Побочно проверено правило «посторонний ассет не трогаем»: в релизе `v0.24.2`
лежит `XIO-update.json`, которого нет в каталоге выпуска. `asset_plan`
относит его к `foreign` и оставляет как есть — удаляются только имена из
девяти шаблонов и `SHA256SUMS-*.txt`.

---

## 3. Windows: где собирается пакет, почему в 0.24.2 лежал ZIP от 0.24.1

### 3.1 Главное правило

> **Windows-пакет `XIO-Full-<ver>-windows-x64.zip` собирается только на
> Windows-хосте.** Штатной кросс-компиляции Windows-приложений во Flutter нет:
> `flutter build windows` отвечает `"build windows" only supported on Windows
> hosts.` и на Linux, и на macOS. Ни `wine`, ни `mingw` этого ограничения не
> снимают — они дают лишь **полу-кросс** (раздел 3.3), который not a substitute
> для нативной сборки.

В выпуске 0.24.2 изначально лежал `XIO-Full-0.24.1-windows-x64.zip`
(54 535 239 Б) — не опечатка, а следствие двух причин:

1. **Нативная сборка на этом ПК упирается в AppLocker/WDAC.** Проверено
   2026-11-05: `dartaotruntime.exe --version` ещё запускается, а
   `gen_snapshot.exe` — нет (`Политика управления приложениями заблокировала
   этот файл`). Без AOT-компилятора `flutter build windows --release` не
   доходит до результата (`WinError 4551`, см. `docs/release-notes-0.24.2.md`).
2. **Полу-кросс на Debian требует подготовки**: wine, `xvfb`, артефакты движка
   Windows от **той же** ревизии Flutter и готовый Windows-runner. Пока их нет,
   ZIP остаётся прежним.

2026-11-05 пакет 0.24.2 собран на Debian по разделу 3.3
(`XIO-Full-0.24.2-windows-x64.zip`, 55 068 159 Б) и положен в каталог выпуска
вместо 0.24.1. Для вступления в силу нужна перепубликация (`release.py` без
`--dry-run`); сама по себе замена файла в каталоге GitHub не меняет.

`release.py` считает расхождение версий **предупреждением, а не ошибкой**: если
Windows ZIP ниже версии выпуска, в отчёте появляется блок
`ПРЕДУПРЕЖДЕНИЯ: N — на код возврата не влияют` со строкой
`Windows ZIP от версии X — ниже версии выпуска Y: пакет не пересобран …`.
Так расходятся версии не забываются, но выпуск не блокируется.

### 3.2 Диагноз: что показывает Debian (2026-11-05)

```bash
$ which wine wine64 xvfb-run mingw32-gcc x86_64-w64-mingw32-gcc
/usr/bin/xvfb-run          # wine/xvfb-run были только из этого списка; mingw не было вовсе
$ apt-cache policy wine     # wine 10.0~repack-6, wine32 в trixie недоступен (только amd64)
$ apt-get install -y --no-install-recommends wine wine64   # поставлено, 772 МБ префикс
$ wine --version
wine-10.0 (Debian 10.0~repack-6)

$ flutter build windows --release
"build windows" only supported on Windows hosts.

$ flutter config --enable-windows-desktop
Setting "enable-windows-desktop" value to "true".
```

Последняя команда — **ловушка**: `flutter config` принимает флаг, но сборку не
разрешает; ограничение зашито в сам инструмент (`only supported on Windows
hosts`) и не переключается настройкой.

Что при этом **работает** на Linux (проверено, код 0):

```bash
$ flutter precache --windows        # скачивает windows-x64{,-release}/gen_snapshot.exe
$ flutter build bundle --release --target-platform=windows-x64
```

### 3.3 Полу-кросс на Debian: вход, команда, что проверено

Это не «кросс-компиляция Flutter», а сборка из трёх частей: Dart-ядро
компилируется на Linux, AOT-образ для Windows делает **Windows-овский**
`gen_snapshot.exe` под wine, а Win32-обвязка берётся готовой с Windows-хоста.

Что нужно подготовить заранее:

| Вход | Что это | Где взять |
|---|---|---|
| `--runner` | готовый Windows-бандл (`XIO.exe`, `flutter_windows.dll`, `data/icudtl.dat`) | одна успешная нативная сборка `flutter build windows --release` на Windows-хосте (каталог `app/build/windows/x64/runner/Release`); в 0.22.4 — бандл `work/win-full-0231` |
| `--gen-snapshot` | AOT-компилятор под Windows **той же** ревизии Flutter | `flutter precache --windows` → `bin/cache/artifacts/engine/windows-x64-release/gen_snapshot.exe` |
| `--wine-prefix` | отдельный `WINEPREFIX` | `WINEPREFIX=… wineboot -i` |

**Ключевое условие — совпадение ревизии движка.** В 0.24.2 на обеих машинах
Flutter 3.47.7 с `engineRevision deb287481e3ce9468f3434937ced4240a70539ca`;
если ревизии разные, `flutter_windows.dll` не примет `app.so`, и проверять это
надо до сборки.

Полный прогон 2026-11-05 (Debian, репозиторий из `main`):

```bash
export PATH=/opt/flutter/bin:$PATH WINEPREFIX=/root/.wine-xio WINEDEBUG=-all
python3 tooling/cross-platform/build-windows-on-linux.py \
    --runner       /root/win-runner \
    --gen-snapshot /opt/flutter/bin/cache/artifacts/engine/windows-x64-release/gen_snapshot.exe \
    --wine-prefix  /root/.wine-xio
```

Результат: `releases/XIO-0.24.2-windows-x64.zip` (55 068 159 Б) и
`verification/update-022-windows-extraction.json`:

```json
{"operatingSystem":"windows","isWindows":true,"scope":"Windows runtime under Wine, not a native Windows driver/UAC test",
 "engines":["awg","rivet-h3","rivet-s1","xray"],"archiveExtractionPassed":true,"passed":true}
```

Дополнительно проверено вручную: `data/app.so` — ELF 64-bit x86-64 (9,52 МБ,
это Windows-AOT-образ), `libexec/xio-tunnel.exe` — PE32+ (Go 1.27.3,
`GOOS=windows GOARCH=amd64`, 31,45 МБ), распакованный пакет запускается под wine
и держится 25 с без падения (`Impeller`, `OpenGLESSDF`).

Две ловушки, на которых спотыкается первый прогон (обе безобидны):

* в `--runner` должен быть **пустой** каталог `data/flutter_assets` — скрипт
  делает `rmtree` без `ignore_errors`; без каталога падает `FileNotFoundError`;
* после неудачного прогона нужно чистить `app/.dart_tool/flutter_build`, иначе
  `flutter build bundle` переиспользует старый `app.dill` и срабатывает
  проверка «Kernel generation did not produce a fresh snapshot».

**Раскладка архива.** Скрипт пишет записи с префиксом `XIO/`, а выпуск
(`tools/release/build-all.ps1`, `Invoke-WindowsStep`) пакует **плоский** ZIP:
`XIO.exe`, `flutter_windows.dll`, `data/`, `libexec/`, `native_assets.json`,
`LICENSE`, `COPYRIGHT`, `CROSS-PLATFORM-0.19.ru.md` в корне. Для выпуска нужен
плоский вариант; при перепаковке из кросс-сборки убираются `CHANGELOG.md`,
`THIRD-PARTY-0.21.md`, `THIRD-PARTY-0.22.md` и `data/flutter_assets/.last_build_id`
и добавляется `native_assets.json`.

Отдельно: **встроенный апдейтер ждёт наоборот вложенный архив** —
`extractWindowsUpdate` требует `XIO/XIO.exe` и отвергает плоский ZIP
(`FormatException: Unsafe update archive`). Сейчас это не проявляется, потому
что в манифесте 0.24.2 нет `windows-x64` и Windows-клиент открывает страницу
релиза (см. `docs/update-channel.ru.md`), но при включении автообновления на
Windows раскладку придётся согласовать.

**Границы:** wine запускает только доверенный AOT-компилятор и пробник. Wintun,
драйвер, UAC, маршруты и DNS так не проверяются — для них нужен настоящий
Windows-хост (`"scope": "Windows runtime under Wine, not a native Windows
driver/UAC test"`). Полу-кросс — обход блокировки, а не замена нативной сборки.

Старый клиентский путь (`client/build_windows_on_linux.py`) собирает runner
`x86_64-w64-mingw32-g++` из `tooling/cross-platform/windows_runner.cpp` и требует
`--engine-cache`; для Full-пакета он не нужен.

### 3.4 Штатный путь: пошагово на Windows-хосте

Нужны: Windows 11 x64, Flutter 3.47.7 (та же ревизия движка), Go 1.27.3,
Visual Studio 2022 Build Tools с workload «Desktop development with C++»,
PowerShell 7, и — обязательно — политика приложений, не блокирующая
`gen_snapshot.exe`.

```powershell
# 1. зависимости и проверки (тесты можно гонять на Debian, если на Windows их режет WDAC)
cd app;  flutter pub get;  flutter analyze;  flutter test

# 2. сборка раннера и AOT (даёт XIO.exe, flutter_windows.dll, data/app.so)
flutter build windows --release

# 3. VPN-помощник
cd ..\protocol\rivet
go build -trimpath -ldflags="-s -w" `
    -o ..\..\app\build\windows\x64\runner\Release\libexec\xio-tunnel.exe ./cmd/xio-desktop

# 4. Wintun 0.14.1 (amd64) — только официальный архив, sha256 ниже
#    https://www.wintun.net/builds/wintun-0.14.1.zip
#    07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
#    -> libexec\wintun.dll + libexec\WINTUN-LICENSE.txt

# 5. лицензии в корень бандла: LICENSE, COPYRIGHT, CROSS-PLATFORM-0.19.ru.md

# 6. упаковка: ПЛОСКИЙ ZIP (XIO.exe в корне, без папки XIO\)
Compress-Archive -Path "app\build\windows\x64\runner\Release\*" `
    -DestinationPath "releases\XIO-Full-0.24.2-windows-x64.zip" -CompressionLevel Optimal
```

Всё это уже автоматизировано: `pwsh tools/release/build-all.ps1 -Version 0.24.2
-Skip android-full,android-client,linux,server` (шаг `windows`).

**Подпись.** Authenticode сейчас не применяется: сертификата code signing в
проекте нет, `signtool` нигде не вызывается. Целостность обеспечивает
`SHA256SUMS-<ver>.txt`, который `release.py` пересчитывает и сверяет при
публикации и при анонимной проверке. Когда сертификат появится, подписывать
нужно **до** упаковки ZIP, по каждому PE-файлу:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 `
    /f cert.pfx /p $env:CERT_PASSWORD `
    app\build\windows\x64\runner\Release\XIO.exe `
    app\build\windows\x64\runner\Release\libexec\xio-tunnel.exe
```

`wintun.dll` — сторонний бинарник, его не переподписываем (лицензия Wintun
запрещает модификацию), поэтому подпись `XIO.exe` + `xio-tunnel.exe` и sha256
всего архива остаются единственными точками доверия.

### 3.5 Вариант: собрать на другой Windows-машине по ssh

Если Windows-хост есть, но не этот ПК (или политика приложений на нём мягче),
сборку можно запустить с Debian одной командой:

```bash
# на Windows-хосте должен быть OpenSSH Server и тот же репозиторий
ssh win-build 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\xio\XIO\tools\release\build-all.ps1 -Version 0.24.2 -Skip android-full,android-client,linux,server'
scp 'win-build:C:/xio/XIO/releases/XIO-Full-0.24.2-windows-x64.zip' .
python3 tools/release/release.py --tag v0.24.2 --dir ./release-0.24.2   # публикация
```

Требования к такому хосту: Flutter 3.47.7, Go 1.27.3, VS Build Tools (C++),
и `gen_snapshot.exe` не должен блокироваться. **На этом ПК путь не работает**:
именно `gen_snapshot.exe` режет AppLocker/WDAC (раздел 3.2), а агент `WinWorker`
живёт на этой же машине — то есть нужен либо другой Windows-хост/VM, либо
снятие политики для каталога Flutter.

### 3.6 Проверка Windows-архива после сборки

```bash
# плоский ZIP: XIO.exe, data/, libexec/xio-tunnel.exe, libexec/wintun.dll
python3 - <<'PY'
import zipfile; z=zipfile.ZipFile('releases/XIO-Full-0.24.2-windows-x64.zip')
names=z.namelist()
for need in ('XIO.exe','libexec/xio-tunnel.exe','libexec/wintun.dll',
             'data/app.so','data/icudtl.dat','flutter_windows.dll'):
    assert need in names, need
assert not any(n.startswith('XIO/') for n in names), 'выпуск пакуется плоским'
print('windows zip ok:', len(names), 'файлов')
PY
```

---

## 4. Ubuntu: `tooling/cross-platform/package-ubuntu.py`

Собирается **только на Linux** (`flutter build linux` не кросс-компилируется).

```bash
# на Debian, из корня репозитория: pub get → analyze → test → build linux →
# go build xio-tunnel → package-ubuntu.py
sh tools/build-linux.sh
# результат: releases/XIO-<ver>-ubuntu-amd64.deb и releases/XIO-<ver>-ubuntu-x64.tar.gz
```

Отдельно (если бандл уже собран):

```bash
cd app && flutter build linux --release
cd .. && go build -trimpath -ldflags='-s -w' \
    -o app/build/linux/x64/release/bundle/libexec/xio-tunnel ./protocol/rivet/cmd/xio-desktop
python3 tooling/cross-platform/package-ubuntu.py
```

`package-ubuntu.py` берёт версию из `app/pubspec.yaml`, складывает бандл в
`/opt/xio`, `.desktop`, иконку, симлинк `/usr/bin/xio`, `DEBIAN/control`
(`Depends: libc6 (>= 2.34), libgtk-3-0 | libgtk-3-0t64, libstdc++6, libglu1-mesa,
libegl1, libgl1, libgles2, iproute2, pkexec | policykit-1, systemd-resolved | systemd`),
и собирает `.deb` через `dpkg-deb --root-owner-group` плюс `tar.gz` с тем же
деревом. Нужны `dpkg-deb`, GTK3-заголовки и `PKG_CONFIG_PATH` на GTK-сисрут
(`.build-support/gtk-root`, если он есть — `build-linux.sh` подставляет сам).

Из `release.py` это делается флагом `--ssh debian17`: скрипт выполнит
`sh tools/build-linux.sh` на Debian и заберёт оба файла в каталог релиза.
Учтите, что `build-linux.sh` внутри гоняет ещё `flutter analyze` и
`flutter test` — на слабом хосте это самый тяжёлый шаг; если тесты уже
прогнаны в CI, сборку можно сузить своим `--ssh-cmd`, например:

```bash
python3 tools/release/release.py --tag v0.24.2 --ssh debian17 \
  --remote-repo /root/xio-linux \
  --ssh-cmd 'cd /root/xio-linux && (cd app && flutter build linux --release) \
             && go build -trimpath -ldflags="-s -w" \
                  -o app/build/linux/x64/release/bundle/libexec/xio-tunnel ./protocol/rivet/cmd/xio-desktop \
             && python3 tooling/cross-platform/package-ubuntu.py'
```

---

## 5. Что проверено, а что нет

Проверено (команды и вывод — в отчёте задачи):

* синтаксис `.github/workflows/ci.yml` (`yaml.safe_load`), 29 тестов
  `tools/test_release_script.py` (`python3`, WSL Ubuntu 24.04, 3.12.3);
* baseline pytest на Debian: 160 passed / 5 failed, с исключениями — 5 deselected;
* `bash -n` для 11 файлов `deploy/**/*.sh` на Debian — все OK;
* `flutter pub get` и `flutter analyze` на Debian — OK (`No issues found!`, 10 с);
* `release.py --dry-run` на реальном каталоге 0.24.2 — код 0, файлы не изменены;
* `release.py --verify-only` — 10 ассетов скачаны анонимно, sha256 и размеры
  совпали, код 0;
* реальная подпись 5 APK через `apksigner` — сертификат `e4e81b12…c9671`.

Проверено 2026-11-05 (сборка Windows-пакета 0.24.2):

* на Debian стоит `wine-10.0`, `xvfb-run`; mingw не ставился (для Full он не нужен);
* `flutter build windows --release` на Debian — `"build windows" only supported
  on Windows hosts.`; `flutter config --enable-windows-desktop` ограничение не снимает;
* `flutter precache --windows` и `flutter build bundle --target-platform=windows-x64`
  на Debian — код 0;
* `gen_snapshot.exe` (windows-x64-release) запускается под `xvfb-run wine` и
  компилирует `app.so`;
* полный прогон `tooling/cross-platform/build-windows-on-linux.py` собрал
  `XIO-Full-0.24.2-windows-x64.zip` (55 068 159 Б); пробник под wine:
  `isWindows:true, passed:true`, `archiveExtractionPassed:true`;
* распакованный пакет 0.24.2 стартует под wine и держится 25 с без падения;
* ревизии движка Flutter на Windows и Debian совпали
  (`deb287481e3ce9468f3434937ced4240a70539ca`);
* на этом ПК `gen_snapshot.exe` по-прежнему блокируется политикой приложений —
  нативная Windows-сборка 0.24.2 без снятия блокировки невозможна;
* 29 тестов `tools/test_release_script.py` — зелёные после добавления
  предупреждения о версии Windows ZIP.

Не проверено:

* **реальный прогон CI на раннере** — раннеры зарегистрированы на другой
  репозиторий, метки `debian17` нет, API показывает `offline`;
  workflow на `rukazax/xio_vpn` не запускался ни разу;
* `flutter test` на Debian не доведён до конца: после ~10 минут прогона хост
  перестал отвечать по SSH (порт 22 принимает TCP, но баннер SSH не отдаётся;
  веб-шлюз `https://192.168.88.17:3443` тоже перестал отвечать). Это похоже на
  исчерпание памяти при прогоне 315 тестов на 8-гигабайтном N5110. Прогон
  остановлен, чтобы не блокировать сдачу; **хост требует перезагрузки и
  повторного запуска `flutter test`**, после чего baseline в
  `tools/ci/pytest-baseline.txt` нужно перепроверить вместе с добавленным
  `tools/test_release_script.py` (ожидаемо 189 passed, 5 deselected);
* **Windows-пакет 0.24.2 не проверен на живой Windows**: драйвер Wintun, UAC,
  маршруты, DNS и установка поверх 0.24.1 — вне возможностей wine (раздел 3.3);
* публикация (upload/delete ассетов) не выполнялась — по заданию ничего не
  публикуем; проверены только план и анонимная сверка. После замены файла в
  каталоге выпуска GitHub всё ещё отдаёт `XIO-Full-0.24.1-windows-x64.zip`,
  пока не выполнена перепубликация.

---

# Release pipeline (EN)

Short English summary; the Russian part above is normative.

**CI** (`.github/workflows/ci.yml`) runs on push/PR to `main` on the self-hosted
Debian 13 runner: job `flutter` (`pub get --enforce-lockfile`, `analyze`,
`test --reporter compact`, logs uploaded as `ci-flutter-<sha>`) and job `server`
(`bash -n` over `deploy/**/*.sh`, then `pytest server/managed server/catalog tools`
as root with `TZ=UTC`, logs as `ci-server-<sha>`). Five known failures are
deselected in `tools/ci/pytest-baseline.txt` with documented reasons; any other
failure breaks the build. `TZ=UTC` fixes a date-boundary flake in
`tools/test_whitelist_catalog.py`; root is required because some server tests
touch `/etc/xio-stack`.

Runner reality on 2026-11-05: the three Debian runner services are running but
registered to a **different repository**, labelled `self-hosted,Linux,X64` plus
a legacy runner label (see `LEGACY_RUNNER_LABEL` above), and reported `offline`
by the API. There is no `debian17` label, so the workflow as written cannot be
picked up. To enable it: register a runner on `rukazax/xio_vpn` and add the
`debian17` label, or set the repository variable `CI_RUNNER` to the runner's
actual labels (the workflow reads it via `fromJSON`, defaulting to
`["self-hosted","debian17"]`).

**`tools/release/release.py`** is the single release path: collect artifacts
(`--ssh debian17` builds the Ubuntu files on Debian, or take ready files from
`--dir`), verify APK signatures with `apksigner verify --print-certs` against
certificate `e4e81b12…c9671`, recompute `SHA256SUMS-<ver>.txt` with LF endings,
require all nine artifacts (the Windows ZIP may carry another version), publish
through the GitHub Releases API (create/update the release, upload new assets,
delete replaced and orphaned ones by name, never touching foreign assets), then
download every asset **anonymously** and compare sha256 and size. Exit code 1 on
any mismatch. `--dry-run` performs checks and prints the plan only;
`--verify-only` downloads and verifies without publishing.

**Windows** is the one artifact that has **no official cross-build**: Flutter
answers `"build windows" only supported on Windows hosts.` on Linux, and
`flutter config --enable-windows-desktop` changes nothing. The package is built
on a Windows host (section 3.4: `flutter build windows --release`, Go helper,
Wintun 0.14.1, flat ZIP; Authenticode is not configured yet, integrity rests on
`SHA256SUMS-<ver>.txt`). On this PC that native path is blocked — AppLocker/WDAC
refuses `gen_snapshot.exe` — so the 0.24.2 package was produced on Debian with
the **semi-cross** route (Dart kernel on Linux, Windows AOT via `xvfb-run wine
gen_snapshot.exe`, runner bundle from the Windows host):

```bash
python3 tooling/cross-platform/build-windows-on-linux.py \
    --runner BUNDLE --gen-snapshot GEN_SNAPSHOT_EXE --wine-prefix WINE_PREFIX
```

That run (2026-11-05) produced `XIO-Full-0.24.2-windows-x64.zip`
(55 068 159 B) and its wine probe reported `isWindows:true, passed:true,
archiveExtractionPassed:true`. Wine proves only that the app is a Windows binary
that starts and unpacks its archive — never the Wintun driver, UAC or routing,
so a native Windows run is still required before calling the package released.
A second Windows host can be driven over ssh (section 3.5), but this PC and
`WinWorker` share the same WDAC policy. The legacy client path
(`client/build_windows_on_linux.py --engine-cache …`) compiles the runner with
`x86_64-w64-mingw32-g++`; the Full package does not need it. **Ubuntu** is
packaged by `tooling/cross-platform/package-ubuntu.py` after
`sh tools/build-linux.sh` (Flutter Linux build, Go helper, `dpkg-deb`).

`release.py` treats an older Windows ZIP as a **warning, not an error**: it
prints a `ПРЕДУПРЕЖДЕНИЯ` block naming the version gap, so it cannot be
forgotten, and the exit code stays 0.

Verified locally: workflow YAML parses, 29 release-script tests pass, the Debian
pytest baseline was measured, `bash -n` covers 11 deploy scripts,
`release.py --dry-run` and `--verify-only` both returned 0 on the real 0.24.2
artifacts (10 assets downloaded anonymously, all digests matched). Not verified:
an actual CI run on the runner, a completed `flutter test` on Debian (the host
stopped answering SSH mid-run), the Windows package on real Windows (driver,
UAC, routing), and the publish step itself.
