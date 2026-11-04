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

## 3. Windows: почему в 0.24.2 лежит ZIP от 0.24.1 и как пересобрать

### 3.1 Почему 0.24.1

В выпуске 0.24.2 файл называется `XIO-Full-0.24.1-windows-x64.zip`
(54 535 239 Б) — это не опечатка. Причины, зафиксированные в
`docs/release-notes-0.24.2.md`:

1. **Нативная сборка на Windows-хосте заблокирована** WDAC/Smart App Control:
   `dartaotruntime.exe`, `gen_snapshot.exe`, `impellerc.exe`, `flutter_tester.exe`
   не запускаются (`WinError 4551`). Поэтому APK и тесты идут на Debian, а
   Windows-часть собирается отдельно.
2. **Кросс-сборка на Debian требует подготовленного входа** — прекомпилированный
   Windows-runner и `gen_snapshot.exe` ровно от той ревизии Flutter, что в
   `pubspec.lock`/SDK. Пока их нет, ZIP остаётся прежним.
3. Итог в самом документе: «Windows-сборка в этом релизе может быть от rc13 —
   если пересборка не успеет, ZIP останется прежним». Так и вышло.

Важно: `release.py` считает такую ситуацию **предупреждением, а не ошибкой**
(`! Windows ZIP от версии 0.24.1`), потому что это осознанное состояние
выпуска, а не битый набор.

### 3.2 Кросс-сборка на Debian (wine + mingw, engine cache)

Основной поддерживаемый путь для Full-сборки — штатный:

```bash
# на Debian, из корня репозитория
python3 tooling/cross-platform/build-windows-on-linux.py \
    --runner   /path/to/windows-runner-bundle   \
    --gen-snapshot /path/to/gen_snapshot.exe     \
    --wine-prefix /path/to/private/wineprefix
```

Что нужно подготовить заранее:

| Вход | Что это | Где взять |
|---|---|---|
| `--runner` | готовый Windows-бандл Flutter (XIO.exe, `flutter_windows.dll`, `data/icudtl.dat`) | одна успешная нативная сборка `flutter build windows --release` на Windows-хосте; в 0.22.4 использовался бандл из `work/win-full-0231` |
| `--gen-snapshot` | AOT-компилятор под Windows **той же** ревизии Flutter (3.47.7) | артефакты движка Windows: `flutter precache --windows`, каталог `engine/windows-x64*/gen_snapshot.exe` |
| `--wine-prefix` | отдельный `WINEPREFIX` | создаётся один раз: `WINEPREFIX=… wineboot -i`; приватный префикс нужен, чтобы не конфликтовать с другой Wine-сессией |

Скрипт делает всё остальное: `flutter build bundle --target-platform=windows-x64`,
подменяет `data/flutter_assets`, гоняет `xvfb-run -a wine gen_snapshot.exe
--deterministic --snapshot_kind=app-aot-elf --strip` (ELF-образ для Windows
engine), собирает архив и **проверяет его на себе**: запускает пробник под Wine
(`Platform.isWindows`, семь движков, распаковка ZIP) и пишет
`verification/update-0XX-windows-extraction.json`.

Старый путь (клиентская сборка) с `engine cache` и mingw — в
`client/build_windows_on_linux.py`:

```bash
python3 client/build_windows_on_linux.py \
    --engine-cache   /path/to/engine/windows-cache \
    --runtime-template /path/to/windows-runtime \
    --wine-prefix    /path/to/wineprefix
```

Здесь `--engine-cache` — каталог артефактов движка Flutter для Windows, откуда
берутся `release/` (заголовки `flutter_windows.h`, `libflutter_windows.a`) и
`debug/gen_snapshot.exe`; runner (`runner.cpp` из
`tooling/cross-platform/windows_runner.cpp` + ресурсы `.rc`) компилируется
`x86_64-w64-mingw32-g++`/`-windres` прямо на Debian.

Требования к Debian-хосту: `wine`, `xvfb-run` (`xvfb`), `x86_64-w64-mingw32-g++`
и `-windres` (`g++-mingw-w64-x86-64`, `binutils-mingw-w64-x86-64`), Go для
`xio-tunnel.exe` (`GOOS=windows GOARCH=amd64 CGO_ENABLED=0`), Flutter 3.47.7.

**Границы:** Wine запускает только доверенный AOT-компилятор и пробник. Ни
Wintun, ни драйвер, ни UAC, ни маршруты/DNS так не проверяются — для них нужен
настоящий Windows-хост. Об этом же говорит `verification/update-022-windows-extraction.json`
(`"scope": "Windows runtime under Wine, not a native Windows driver/UAC test"`).

### 3.3 Проверка Windows-архива после сборки

```bash
# состав плоского ZIP: XIO.exe, data/, libexec/xio-tunnel.exe, libexec/wintun.dll
python3 - <<'PY'
import zipfile; z=zipfile.ZipFile('releases/XIO-0.24.2-windows-x64.zip')
names=z.namelist()
for need in ('XIO/XIO.exe','XIO/libexec/xio-tunnel.exe','XIO/libexec/wintun.dll'):
    assert need in names, need
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
* Windows-кросс-сборка не выполнялась: на Debian не проверялось наличие
  `wine`/`xvfb-run`/`mingw` (SSH был недоступен), прекомпилированного Windows
  runner и `gen_snapshot.exe` под рукой нет;
* публикация (upload/delete ассетов) не выполнялась — по заданию ничего не
  публикуем; проверены только план и анонимная сверка.

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

**Windows** stays at 0.24.1 in the 0.24.2 release because the native Windows
build is blocked by WDAC (`dartaotruntime.exe`, `gen_snapshot.exe`,
`impellerc.exe`, `flutter_tester.exe` fail with `WinError 4551`) and the Debian
cross-build needs a prebuilt Windows runner plus a `gen_snapshot.exe` from the
same Flutter revision:

```bash
python3 tooling/cross-platform/build-windows-on-linux.py \
    --runner BUNDLE --gen-snapshot GEN_SNAPSHOT_EXE --wine-prefix WINE_PREFIX
```

The legacy client path (`client/build_windows_on_linux.py --engine-cache …`)
compiles the runner with `x86_64-w64-mingw32-g++` and runs the trusted AOT
compiler under `xvfb-run wine`. Wine proves only that the app is a Windows
binary that starts and unpacks its archive — never the Wintun driver, UAC or
routing. **Ubuntu** is packaged by `tooling/cross-platform/package-ubuntu.py`
after `sh tools/build-linux.sh` (Flutter Linux build, Go helper, `dpkg-deb`).

Verified locally: workflow YAML parses, 29 release-script tests pass, the Debian
pytest baseline was measured, `bash -n` covers 11 deploy scripts,
`release.py --dry-run` and `--verify-only` both returned 0 on the real 0.24.2
artifacts (10 assets downloaded anonymously, all digests matched). Not verified:
an actual CI run on the runner, a completed `flutter test` on Debian (the host
stopped answering SSH mid-run), the Windows cross-build, and the publish step
itself.
