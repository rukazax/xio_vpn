# XIO: отвязка от прежнего имени x1o — инвентарь и результат

Дата: 2026-11-05. Ветка: `agent/dex1o` (worktree `work/agent-dex1o`).
База: `f70d05e` (HEAD `merge/0.24.1`).

## 0. Расхождения с постановкой

1. **Ветка/база.** В постановке: «`repo-merge`, ветка `main` (HEAD `f70d05e`)». Фактически
   `work/repo-merge` стоит на `merge/0.24.1` с HEAD `f70d05e`, а `origin/main` = `fff525e`;
   `f70d05e` **не** предок `origin/main` (`merge/0.24.1` ahead 9, local `main` behind 144).
   Ветка создана от `f70d05e` (по HEAD из постановки), иначе потерялись бы 9 коммитов интеграции.
2. **Что такое `x1o` в этом репозитории.** Это не только ссылка на посторонний проект: `x1o`
   («X in, 1 out») — **собственное прежнее имя XIO** (релизы 0.1–0.22, шрифты `X1oSans`,
   CN сертификата подписи, схема `x1o://`). Реальная межпроектная связь в дереве одна —
   CI-раннеры, зарегистрированные на чужой репозиторий (см. §3.1). Поэтому «удалить всё»
   означало бы переписать историю продукта; чистка разделена на активный продукт и архив.
3. **Baseline тестов** (см. §7) не совпал с ожидаемым в постановке: на Debian проверки
   недоступны (SSH не отвечает), всё гонялось в WSL Ubuntu-24.04, поэтому числа другие.

## 1. Метод

```
git grep -n -i --untracked 'x1o'        # регистр не важен, цифра 1 (не буква i)
```

494 строки вывода, из них 9 — `Binary file … matches`: случайные байты в
`libxio_openvpn.so` (×3), `rivet.aar`, `mobile.aar` (×2), `NotoSansCJKsc-Regular.otf`,
`xio-server.tar.gz`, `xio.ico`. Это не ссылки и не текст — не правились.
**Текстовых вхождений: 485 в 82 файлах.**

## 2. Инвентарь: было (485)

| Категория | Строк | Файлов | Что это |
|---|---:|---:|---|
| (a) документация | 54 | 24 | README.md/README.ru.md, CHANGELOG, `docs/**` (в т.ч. blog, compatibility, verification, release notes), `verification/*.md`, `brand/mark.svg`, README тулинга (`tools/ci`, `tools/release`) |
| (b) код и скрипты | 36 | 20 | `app/lib/**`, `app/pubspec.yaml`, Android (gradle, proguard, MainActivity), `server/webui/xio-webui.service`, `tools/**`, `client/build.py`, `lab*/go.mod`, `lab-share-receiver`, `work/verify-all.ps1` |
| (c) тесты | 25 | 10 | `app/test/**`: имена font family и литералы `x1o://` |
| (d) `work/` | 9 | 2 | архив отчётов (`xio-joint-log.md`, `verify-all.ps1`) |
| (e) `history/` — доки | 161 | 16 | README релизов 0.1–0.16.1 + PRODUCT-BRIEF |
| (e) `history/` — код | 87 | 3 | снимки `admin.py` 0.12/0.13/0.15 |
| (f) `verification/*.log` | 105 | 4 | машинные логи прогонов 0.20 (в т.ч. `flutter-tests-020.log` — 102) |
| (g) vendor-хеши | 8 | 8 | base64/`integrity` в `vendor/**`, `native-sources/**` — ложные совпадения |

## 3. Что удалено/переписано (активный продукт)

### 3.1 Реальная межпроектная связь — убрана полностью

- `docs/release-process.ru.md` (14 → 1): удалены имена чужого репозитория
  (`rukazax/x1o`), `"gitHubUrl"`, `actions.runner.rukazax-x1o.*`, каталоги
  `/home/ii/x1o-runner{,2,3}`, имя раннера `debian17-x1o`. Формулировка теперь:
  «раннеры зарегистрированы на другой репозиторий, поэтому workflow этого
  репозитория их не видит». Метка раннера вынесена в явную константу
  `LEGACY_RUNNER_LABEL = "x1o-debian"` с комментарием (иначе оператор не сможет
  сопоставить `CI_RUNNER` с реальным раннером).
- `tools/ci/README.md` (2 → 0): «привязаны к другому репозиторию и носят метку
  устаревшего имени ранних сборок».
- `tools/ci/ci.yml.template` (2 → 0): комментарий без имени чужого репозитория и метки.

### 3.2 Упоминания x1o как другого продукта/панели

- `docs/optimization-0.24.1.ru.md`: «нагрузка панели `x1o`» → «нагрузка служебной
  панели на VPS»; заголовок «### Панель `x1o`» → «### Служебная панель на VPS».
- `docs/verification/tg211-*.ru.md` (3 файла): «XIO VPN only (не x1o)» → «только XIO VPN».
- Остальные вхождения в этих отчётах — пути устаревшего серверного архива
  (`/etc/x1o-managed` и счётчики вхождений) — предмет самого отчёта, не правились.

### 3.3 Брендинг активных документов

- `brand/mark.svg`: `aria-label="x1o: X in, 1 out"` → `"XIO: X in, 1 out"`.
- `docs/compatibility/0.23.0.ru.md` / `.en.md`: «переименование `x1o` → `XIO`» →
  «переименование прежнего имени проекта → `XIO` (устаревшее имя ранних сборок)».
- `README.md`, `README.ru.md`, `docs/release-notes-0.24.1-mobile.md`: CN сертификата
  подписи оставлен как факт, но обозначен «сертификат выпуска … (устаревшее имя
  ранних сборок; менять нельзя — иначе обновление не установится поверх)».
- `app/lib/core.dart`: маркер секции предпроверки `printf '\nX1O\n'` → `'\nXIO\n'`
  (строка только выводится пользователю, парсинга нет).
- `docs/blog/*windows-and-ipv6*`: имя интерфейса `x1oawg0` оставлено (это факт
  конфигурации того времени) с пометкой «имя интерфейса ранних сборок».

### 3.4 Код и конфиги

- `app/android/app/proguard-rules.pro`: правила `app.x1o.x1o.*` → `app.xio.xio.*`.
  Это был реальный дефект: настоящие JNI-классы лежат в `app.xio.xio`
  (`OpenVpnBackend.kt`, `OpenVpnNative`), старые правила их не покрывали, а
  `-keep` для несуществующего пакета ничего не делал. Заодно убрано дублирующее
  правило `OpenVpnBackend$Client` (покрыто `$*`).
- `lab/go.mod`, `lab-amnezia/go.mod`, `vps-check/go.mod`: `module app.x1o/...` →
  `app.xio/...` (импортов этого пути в дереве нет, переименование безопасно).
- `app/lib/main.dart`: `extension X1oColors` → `XioColors` (используется неявно,
  на вызовы не влияет).
- `tools/audit-releases.py`: схема вынесена в `LEGACY_SCHEME` (3 литерала → 1).
- `server/webui/xio-webui.service`: к путям с устаревшими именами добавлен
  комментарий «только чтение данных старых установок при миграции; сервис в них
  не пишет».

## 4. Функциональные идентификаторы — сохранены (с комментариями)

| Идентификатор | Где | Почему нельзя менять |
|---|---|---|
| `legacyX1oUriScheme = 'x1o://'` | `app/lib/managed_models.dart:11`, используется `core.dart:472`, `managed_models.dart:295` | приём профилей, выданных старыми версиями (заявлено в CHANGELOG 0.23.0 «приём `x1o://` сохранён») |
| `LEGACY_URI_SCHEME` | `MainActivity.kt:19`, `Receiver.java:16` | те же старые ссылки на Android/lab-приёмнике |
| `LEGACY_SCHEME = b'x1o://'` | `tools/audit-releases.py:6` | аудит должен видеть и старый формат профилей (иначе секреты в них не находятся) |
| `LEGACY_KEY_ALIAS = 'x1oDevelopment'` | `build.gradle.kts:56,71`, `tools/create-signing-key.py:22`, `tools/release/sign-apk.ps1`, `tools/release/README.md` | алиас ключа и CN `x1o Development` — идентичность подписи; смена = APK не установится поверх выпущенных |
| `/etc/x1o-managed`, `/var/lib/x1o-rivet` | `server/webui/xio-webui.service:35`, `:38` | разрешение на чтение данных старых установок. **Замечание:** в текущем `server/**` нет ни одного читателя этих путей (grep пуст) — grant держится «на будущее»; при желании снимается одной строкой |
| `LEGACY_RUNNER_LABEL = "x1o-debian"` | `docs/release-process.ru.md:113` | метка реального раннера на хосте; Debian недоступен, перерегистрировать сейчас нельзя |
| `X1oSans`, `X1oCJK`, `X1oArabic`, `X1oDevanagari`, `X1oEmoji` | `app/pubspec.yaml`, `app/lib/app_theme.dart`, `app/test/**`, `client/build.py`, `docs/screenshots/README.md` | имена font family; переименование требует правки ассетов/подстановки шрифтов в тестах и рискует сборкой — по решению оставлены, в текстах как продукт не упоминаются |
| `'x1o://'` в тестах | `app/test/client_import_test.dart:49`, `managed_models_test.dart:49,77` | это входные данные теста на приём старой ссылки, а не код |

## 5. Архив — не чистится (решение владельца/родителя от 05.11.2026)

- `history/` — 161 строка в 16 документах + 87 строк в 3 снимках `admin.py`.
  Это релизы 0.1–0.16 самого XIO под прежним именем; переписывание путей
  (`/etc/wireguard/x1o0.conf`, `x1o-managed-*`, имена APK в ссылках) исказило бы
  исторические записи.
- `verification/*.log` — 105 строк, машинные логи прогонов 0.20; 102 из них —
  абсолютный путь рабочей копии разработчика (`…/x1o/app/test/...`). Правка
  логов = подделка артефакта.
- `work/` — 9 строк (журнал и `verify-all.ps1`), архив отчётов; плюс этот файл.

## 6. Остаток: было → осталось

| Категория | Было | Осталось | Почему осталось |
|---|---:|---:|---|
| (a) документация | 54 | 31 | CN подписи (3), метка раннера (1), legacy-пути в отчётах tg211 (15), blog `x1oawg0` (2), VERIFICATION 0.10/0.11 (2), CHANGELOG 0.23.0 (3), `tools/release` alias (3), `docs/screenshots` шрифты (1), `verification/0.24.0-release.json` CN (1) |
| (b) код и скрипты | 36 | 24 | константы схемы/алиаса (managed_models 2, core 1, MainActivity 1, Receiver 1, audit 1, create-signing-key 1, build.gradle 2), unit-пути (2), `client/build.py` шрифт (1), `tools/release` alias (7), фикстура apksigner (1), `tools/test_release_script.py` CN (1), `work/` (1) — из них 9 — `work/` вне активного кода |
| (c) тесты | 25 | 25 | font family (22) и входные литералы `x1o://` (3) |
| (d) `work/` | 9 | 9 | архив (не чистится) |
| (e) `history/` | 248 | 248 | архив (не чистится) |
| (f) логи | 105 | 105 | архив (не чистится) |
| (g) vendor-хеши | 8 | 8 | ложные совпадения в base64/`integrity`; правка ломает контрольные суммы |
| **Итого (текст)** | **485** | **450** | плюс 9 `Binary file … matches` — случайные байты |

Полный grep после правок: 459 строк вывода, из них 450 текстовых в 71 файле.
Числа посчитаны **до добавления этого отчёта**; сам отчёт лежит в `work/` (архив)
и в подсчёт активного продукта не входит.
Остаток в **активном продукте** (вне `history/`, `verification/*.log`, `work/` и
vendor-хешей) — 80 строк; разбор:

| Что | Строк | Характер |
|---|---:|---|
| font family `X1o*` (pubspec, app_theme, тесты, `client/build.py`, docs/screenshots) | 31 | идентификатор ассетов, не переименовывался |
| подпись: CN `x1o Development`, алиас/keystore `x1oDevelopment` | 15 | идентичность подписи (README ×2, release notes, tools/release, sign-apk, фикстура, verification json, build.gradle, create-signing-key) |
| константы схемы `x1o://` + её использование | 6 | `legacyX1oUriScheme`, `LEGACY_URI_SCHEME` (Dart/Kotlin/Java/Python) |
| литералы `x1o://` в тестах | 3 | входные данные теста на приём старых ссылок |
| legacy-пути архива 0.20.x в отчётах tg211 | 15 | предмет самих отчётов |
| пути `/etc/x1o-managed`, `/var/lib/x1o-rivet` в unit | 2 | grant на чтение старых данных |
| `x1oawg0` в blog (с пометкой) | 2 | факт конфигурации того времени |
| CHANGELOG 0.23.0 (историческая запись) | 3 | разрешено, без ссылок на чужие репозитории |
| `VERIFICATION-0.10/0.11` (имя AVD, старая схема) | 2 | артефакты проверок |
| метка раннера `LEGACY_RUNNER_LABEL` | 1 | фактическая метка на хосте |

## 7. Проверки

Все прогоны — в WSL Ubuntu-24.04 (`wsl -d Ubuntu-24.04`, Flutter `/opt/flutter`,
Python 3.12.3 + pytest 9.2.0 в `/root/xio-venv`). Debian 192.168.88.17 по SSH
недоступен, поэтому нативной проверки на нём нет.

| Проверка | Baseline (до правок) | После правок |
|---|---|---|
| `flutter analyze` | 0 issues | **0 issues** |
| `flutter test` | 320 passed / 12 skipped / 0 failed | **320 passed / 12 skipped / 0 failed** |
| `pytest -q server/managed server/catalog tools` | 190 passed / 4 failed | **190 passed / 4 failed** (те же 4) |
| `docs/check-docs-links.py` | 6 files, 181 links, 0 errors | **0 errors, 0 warnings** |

Расхождение с постановкой (320/12/0 и 190/4 против 315/10 и 160/5): это другое
окружение — WSL, а не Debian; набор тестов на `f70d05e` больше, чем в ожидаемом
baseline. Красные те же, что и до правок:
`test_admin.py::StaticAwgTests::test_add_awg_returns_profile_and_marks_transport`,
`StaticAwgGuardTests::test_ipv6_host_endpoint_is_bracketed`,
`StaticAwgGuardTests::test_static_peer_does_not_appear_in_wireguard_config`
(отсутствующий `dualstack.cascade_status()`) и
`test_whitelist_catalog.py::RunTests::test_builds_catalog_and_record_provenance`
(зависит от даты/таймзоны: файл каталога `whitelist-20261104.json` против
локальной даты 20261105 — в CI лечится `TZ=UTC`).

## 8. Что не проверено

- **Сборка APK и `gradle`** — не запускались: правка `proguard-rules.pro`,
  `build.gradle.kts`, `MainActivity.kt` проверена только чтением + `flutter analyze`
  (Kotlin/Java не компилировались). Debian недоступен, Android SDK/NDK в WSL не ставились.
- **systemd-юнит** `xio-webui.service` не проверялся (`systemd-analyze verify` требует хост).
- **Go-модули** `lab*`, `vps-check` после переименования не собирались (`go build`).
- **CI на раннере** не запускался: раннеры зарегистрированы на другой репозиторий,
  Debian недоступен; правки только в тексте/комментариях workflow-шаблона.
- **Подпись APK** не перевыпускалась (правился только текст и алиас-константа).
- **history/** и `verification/*.log` не чистились — по решению (см. §5).
- Windows/iOS-сборки не запускались.
