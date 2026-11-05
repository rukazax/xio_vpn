# tools/release — конвейер сборки и публикации XIO

Каталог содержит четыре скрипта PowerShell 7, которыми выпуск собирается, подписывается,
публикуется и проверяется **одной командой на шаг**. Все пути — параметры, секреты в вывод
не попадают, повторный запуск не ломает каталоги.

| Файл | Назначение |
|---|---|
| `build-all.ps1` | последовательная сборка всех артефактов выпуска в один каталог + `manifest.json` |
| `sign-apk.ps1` | подпись APK ключом из параметра/`$env:XIO_KEYSTORE` и проверка `apksigner verify` |
| `publish.ps1` | релиз в GitHub Releases, загрузка ассетов, `SHA256SUMS-<ver>.txt`, сверка digest |
| `verify-release.ps1` | скачать ассеты и сверить sha256 с суммами, таблица OK/FAIL |

Требования: PowerShell 7 (`#Requires -Version 7.0`), Flutter 3.x, Go, Python 3, `curl.exe`
(есть в Windows 10+), Android build-tools (`apksigner`, `zipalign`), `git`.
Для Ubuntu-пакетов — Linux с `dpkg-deb` (Debian 13) либо готовые файлы из `-LinuxArtifacts`.

---

## 1. Порядок выпуска

```powershell
# 0) исходники: свой worktree, vendor-бинарники восстановлены (см. «Типичные ошибки»)
git -C <repo> status --short --branch

# 1) план без сборки: версии, инструменты, команды, имена файлов
pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -DryRun

# 2) сборка (на Windows Ubuntu-пакеты импортируются, см. ниже)
pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -Skip linux

# 3) подпись APK (если нужно переподписать; gradle уже подписывает своим ключом)
$env:XIO_KEYSTORE = 'C:\keys\release-signing.p12'
$env:XIO_KEY_ALIAS = '<алиас из вашего keystore>'
$env:XIO_STORE_PASSWORD = '<пароль>'
$env:XIO_KEY_PASSWORD = '<пароль>'
pwsh -NoProfile -File tools/release/sign-apk.ps1 -Apk "releases/0.24.1/*.apk"

# 4) публикация (сначала DryRun, потом по-настоящему)
pwsh -NoProfile -File tools/release/publish.ps1 -Tag v0.24.1 -NotesFile docs/release-notes-0.24.1.md -AssetsDir releases/0.24.1 -DryRun
pwsh -NoProfile -File tools/release/publish.ps1 -Tag v0.24.1 -NotesFile docs/release-notes-0.24.1.md -AssetsDir releases/0.24.1

# 5) проверка уже опубликованного
pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -Public
```

Ubuntu-пакеты на Windows не собираются (`flutter build linux` требует Linux). Рабочий вариант:

```powershell
# на Debian (репозиторий уже синхронизирован, см. work/flutter-test-debian.ps1)
ssh debian17 'cd <repo> && sh tools/build-linux.sh'

# забрать файлы и влить их в каталог релиза
scp debian17:<repo>/releases/XIO-0.24.1-ubuntu-amd64.deb <out>/
scp debian17:<repo>/releases/XIO-0.24.1-ubuntu-x64.tar.gz <out>/

# либо сразу через build-all с импортом
pwsh -NoProfile -File tools/release/build-all.ps1 -Version 0.24.1 -LinuxArtifacts <repo>/releases
```

---

## 2. `build-all.ps1`

### Шаги (порядок важен)

| Шаг | Что делает | Артефакты |
|---|---|---|
| `server` | `python tools/package-server.py` | `xio-server-<ver>.tar.gz`, `xio-server-release-<ver>.json`; архив и зеркала подкладываются в `app/assets`, после сборки исходные файлы возвращаются |
| `android-full` | `flutter build apk --release --split-per-abi` + universal | `XIO-Full-<ver>-android-<abi>.apk` |
| `android-client` | `python client/build.py --stage <temp> --output-dir <temp>` (внутри сам запускает flutter и `client/verify.py`) | `XIO-Client-<ver>-android-<abi>.apk` (4 ABI) |
| `windows` | `flutter build windows --release`, `go build` помощника, Wintun 0.14.1 с проверкой sha256 | `XIO-Full-<ver>-windows-x64.zip` (плоский ZIP: `XIO.exe`, `data/`, `libexec/`) |
| `linux` | `sh tools/build-linux.sh` на Linux **или** импорт из `-LinuxArtifacts` | `XIO-<ver>-ubuntu-amd64.deb`, `XIO-<ver>-ubuntu-x64.tar.gz` |

Порядок объясняется просто: Full-сборки (Android и Windows) встраивают серверный архив из
`app/assets/xio-server.tar.gz`, поэтому `server` идёт первым.

### Параметры

| Параметр | По умолчанию | Смысл |
|---|---|---|
| `-Version` | обязателен | `0.24.1`; должен совпадать с `version:` в `app/pubspec.yaml` до `+` |
| `-OutDir` | `<repo>/releases/<ver>` | куда складывать артефакты |
| `-Skip` | — | `server`, `android-full`, `android-client`, `windows`, `linux` (через запятую) |
| `-AndroidOnly` | — | то же, что `-Skip windows,linux` |
| `-DryRun` | — | только проверки и план, без записи |
| `-RepoRoot` | на 2 уровня выше скрипта | корень репозитория XIO |
| `-AndroidAbis` | `arm64-v8a,armeabi-v7a,universal` | какие ABI копировать; `x86_64` добавляется явно |
| `-ClientStage` | `<OutDir>/.stage/client` | стейджинг `client/build.py` |
| `-SignApks` + `-Keystore/-KeyAlias/-StorePassword/-KeyPassword/-BuildTools` | — | после сборки вызвать `sign-apk.ps1` (пароли уходят дочернему процессу только через окружение) |
| `-Analyze` | — | дополнительно `flutter analyze` |
| `-LinuxArtifacts` | — | каталог с готовыми Ubuntu-файлами |
| `-KeepAppAssets` | — | не возвращать `app/assets` после сборки |

### Что печатается и что пишется

* для каждого файла: путь, размер, sha256 (и sha256 сертификата для APK);
* `<OutDir>/SHA256SUMS-<ver>.txt` — строки `<sha256>  <имя>`;
* `<OutDir>/manifest.json` — схема 1: версия, время сборки, ветка/коммит и число незакоммиченных
  файлов, версии Flutter/Dart/Go/Python, статусы шагов (`built`/`imported`/`skipped`/`dry-run`),
  список ассетов с размерами и суммами, ограничения.

`manifest.json` намеренно описывает **всё**, включая пропущенные шаги: по нему видно, что выпуск
собран не полностью.

Каждый шаг проверяет результат: APK — `zipalign -c -P 16 4` и `apksigner verify` (нужна схема v2),
ZIP — наличие `XIO.exe`, `libexec/xio-tunnel.exe`, `libexec/wintun.dll`, `data/flutter_assets/...`,
`.deb`/`.tar.gz` — магию формата и правдоподобный размер. При ошибке скрипт падает с понятным
сообщением и кодом 1, не оставляя «полурелиз» молча.

---

## 3. `sign-apk.ps1`

Keystore не захардкожен: `-Keystore` → `$env:XIO_KEYSTORE` → `-SigningProperties`
(`.signing/signing.properties`, ключи `storeFile`/`keyAlias`/`storePassword`/`keyPassword`).

| Параметр | По умолчанию |
|---|---|
| `-Apk` | обязателен, можно `a.apk,b.apk` |
| `-Keystore` | `$env:XIO_KEYSTORE` |
| `-KeyAlias` | `$env:XIO_KEY_ALIAS`, иначе `keyAlias` из `-SigningProperties` |
| `-StorePassword` | `$env:XIO_STORE_PASSWORD` |
| `-KeyPassword` | `$env:XIO_KEY_PASSWORD`, иначе равен паролю хранилища |
| `-OutDir` | — (подпись на месте; с параметром — копии) |
| `-VerifyOnly` | — (ничего не подписывать) |
| `-BuildTools` | `$env:XIO_ANDROID_BUILD_TOOLS` → `$env:ANDROID_HOME/build-tools/<новее>` |

Пароли не попадают ни в argv, ни в лог: apksigner читает их из временной переменной окружения
(`--ks-pass env:...`). Перед подписью проверяется выравнивание (не выровнен — выравнивается
заново), после — `apksigner verify --verbose --print-certs`, требуется схема v2. Печатаются
размер, sha256, sha256 сертификата и набор схем.

---

## 4. `publish.ps1`

| Параметр | По умолчанию | Смысл |
|---|---|---|
| `-Tag` | обязателен | `v0.24.1` |
| `-NotesFile` | `docs/release-notes-<ver>.md`, иначе короткий текст | заметки релиза (markdown) |
| `-AssetsDir` | обязателен | каталог из `build-all.ps1` |
| `-Repo` | `rukazax/xio_vpn` | owner/name |
| `-DryRun` | — | показать план, суммы и список ассетов без сети |
| `-Name` | версия | имя релиза |
| `-Prerelease` / `-Draft` | — | пометки релиза |
| `-TargetCommitish` | ветка по умолчанию | из какого коммита ставить тег |
| `-OnExisting` | `Replace` | `Replace` / `Skip` / `Fail` для уже загруженного ассета |
| `-MaxAttempts`, `-RetryDelaySec` | 5, 5 | повторы загрузки и пауза (дальше удваивается) |
| `-ChunkSizeMB` | 4 | размер блока при потоковом чтении файла для sha256 |
| `-Token`, `-TokenFile` | `%USERPROFILE%\.dsh\secrets\github.json` | токен (`token`/`access_token`); также `$env:GITHUB_TOKEN` |

Что делает:

1. считает sha256 всех файлов из `-AssetsDir` (кроме служебных `*.log`, `.publish-*`),
   пишет `SHA256SUMS-<ver>.txt`;
2. находит релиз по тегу: `PATCH` (обновить заметки/имя) или `POST` (создать);
3. загружает ассеты `curl.exe`, с повторами и экспоненциальной паузой. Заголовок
   `Authorization` лежит в временном файле, который curl читает через `--header @file`
   и который удаляется в `finally` — токена нет в argv и в выводе;
4. при `HTTP 422 already_exists` удаляет конфликтующий ассет (в том числе недокачанный
   «starter» после 502) и повторяет;
5. **проверяет загрузку**: заново читает релиз и для каждого ассета сверяет `state=uploaded`,
   размер и `digest` (`sha256:<hex>`), печатает таблицу и падает, если хоть один не совпал.

Повторный запуск идемпотентен: ассет с тем же digest пропускается, изменённый — удаляется и
загружается заново (`-OnExisting Replace`).

**Про «чанки».** GitHub Releases не поддерживает докачку ассета по `Content-Range`: тело
запроса — весь файл (см. «Upload a release asset» в REST API). Поэтому надёжность даёт не
диапазон, а потоковая передача curl (файл не читается в память целиком) плюс повторы на
уровне ассета и сверка digest после загрузки; sha256 считается блоками по `-ChunkSizeMB`.

---

## 5. `verify-release.ps1`

```powershell
pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -Public
pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -SumsFile releases/0.24.1/SHA256SUMS-0.24.1.txt -Public
pwsh -NoProfile -File tools/release/verify-release.ps1 -Tag v0.24.1 -Assets XIO-Full-0.24.1-android-arm64-v8a.apk,xio-server-0.24.1.tar.gz
```

Суммы берутся из локального `-SumsFile` или из `SHA256SUMS-*.txt` самого релиза. Каждый ассет
скачивается через `curl.exe` (`-Header @file` для приватных репозиториев), sha256 считается
потоком, сравниваются ещё `state`, размер и `digest` из API. Печатается таблица
`АССЕТ | РАЗМЕР | ОЖИДАЕТСЯ | ПОЛУЧЕНО | ИТОГ`; `FAIL` и пропавшие/лишние ассеты — код 1.
`-Public` — анонимно (годится для публичного репозитория), `-KeepDownloads` оставляет файлы.

---

## 6. Типичные ошибки

| Симптом | Причина | Что делать |
|---|---|---|
| `flutter build apk` падает на `android-x64` / процесс `dartaotruntime` заблокирован | AppLocker/WDAC на этом ПК блокирует x64-снапшот Flutter | не просить x86_64: сборка по умолчанию идёт с `--target-platform android-arm,android-arm64`; `x86_64` добавлять только явно через `-AndroidAbis ...x86_64...` |
| `adb install` на MIUI/POCO зависает или `INSTALL_FAILED_*` | MIUI блокирует установку через пакетный установщик | `adb push app.apk /data/local/tmp/` и `adb shell pm install -r /data/local/tmp/app.apk` (при `INSTALL_FAILED_UPDATE_INCOMPATIBLE` — сначала `pm uninstall`, данные теряются) |
| `flutter test` висит/падает на Windows | Smart App Control блокирует `dartaotruntime.exe`, резидентный компилятор Flutter не стартует | тесты гонять на Debian: `pwsh -NoProfile -File work/flutter-test-debian.ps1`; `build-all.ps1` по этой причине `flutter test` не запускает |
| `Клиент нельзя собрать: пины не совпадают` | `client/build.py`/`client/verify.py` закреплены на прежнюю версию (например `0.24.0+5017` при `app/pubspec.yaml 0.24.1+5018`) | поднять `RELEASE`/`VERSION` в `client/build.py` и `RELEASE`/`VERSION_CODE` в `client/verify.py` — это отдельные файлы, `tools/release` их не меняет; либо `-Skip android-client` |
| `tools/package-server.py --check не прошёл: missing pinned inputs` | в свежем worktree нет `vendor-server/*` — готовые бинари не в git (исходники `vendor/amneziawg-go` и `vendor/amneziawg` теперь в git) | собрать/восстановить по `docs/ru/build.md` (`tools/restore-go-sources.py`, `build-rivet.py`, `build-amneziawg.py`, `build-openvpn.py`) |
| `Ubuntu .deb/.tar.gz собираются только на Linux` | `flutter build linux` и `dpkg-deb` недоступны на Windows | собрать на Debian (`sh tools/build-linux.sh`) и передать `-LinuxArtifacts <каталог releases>`, либо `-Skip linux` |
| `Уже создан релиз`/`422 already_exists` | ассет с таким именем уже в релизе | `publish.ps1` сам удаляет и загружает заново; если нужно сохранить — `-OnExisting Skip` / `-OnExisting Fail` |
| `GitHub отклонил токен (HTTP 401)` | нет `repo` в токене или истёк | обновить `%USERPROFILE%\.dsh\secrets\github.json` (поле `token`), проверить `scope`: `repo` |
| `apksigner verify не прошёл … без схемы v2` | APK собран/подписан без v2 | переподписать `sign-apk.ps1` (он включает v1/v2/v3) и повторить `zipalign -f -P 16 4` |
| `Подозрительно маленький файл`/`нет магии` в шаге linux | вместо пакета скопирован HTML/логи | проверить источник `-LinuxArtifacts`; файлы должны называться `XIO-<ver>-ubuntu-amd64.deb` и `XIO-<ver>-ubuntu-x64.tar.gz` |

---

## 7. Ограничения

* `build-all.ps1` собирает артефакты, но **не устанавливает** их на устройство и не проверяет
  живое подключение — это отдельный приёмочный прогон.
* Ubuntu GUI после сборки не запускался; проверяются формат и размер пакетов.
* `publish.ps1` не удаляет лишние ассеты, оставшиеся от прошлых запусков: он предупреждает о них,
  решение — за человеком.
* Скрипты используют `git` только для чтения (ветка/коммит в манифест) и ничего не коммитят.
