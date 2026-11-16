# Android end-to-end validation — 17.11.2026

Стенд: POCO X6 5G, Android 16, Wi-Fi `MY-NET` и мобильная сеть Beeline LTE.
Сервер: основной VPS `81.177.142.37`, пользователь `Telefon KA`, профиль выдан веб-панелью
(`xio://`, schema 1, четыре транспорта: Xray/REALITY, RIVET/H3, RIVET/S1, AmneziaWG).
Приватные ключи и сам профиль в этот отчёт не включены.

## Результат

Штатный профиль веб-панели импортирован начисто и подключён **с первого нажатия** без
перезапуска приложения и без ручных обходов:

| Проверка | Значение |
|---|---|
| Транспорт | AmneziaWG 3.1 |
| Интерфейс | `tun0 = 10.78.0.2/32, fd78:1::2/128` |
| Handshake на сервере | есть, свежий (27 с на момент проверки) |
| Трафик на сервере | 1.19 MiB получено / 19.29 MiB отправлено |
| Выходной IP | `81.177.142.37` (совпадает с публичным адресом VPS) |
| Wi-Fi → LTE | туннель пережил смену сети, endpoint пира обновился на `85.198.104.255` |
| LTE → Wi-Fi | туннель пережил обратную смену, endpoint обновился на Wi-Fi-адрес |

Выходной IP проверялся браузером телефона на `https://api.ipify.org`; shell-команды
`adb shell` намеренно не использовались как доказательство, потому что UID оболочки может
не входить в VPN-маршрут.

## Найденные и исправленные дефекты

### 1. Reconcile на Android отправлял `expectedGeneration = null`

Dart-слой считал, что Android не поддерживает CAS, и всегда передавал `null`. Нативный
журнал в состоянии READY требует точную generation и отвечал `POLICY_STALE`. После каждого
перезапуска приложение не могло согласовать сохранённый план.

Исправление: `policyReconcileGeneration()` в `app/lib/policy_channel.dart`; для Android
generation берётся из READY-состояния (`planGeneration` или вложенный receipt), для desktop
поведение с `casGeneration` не изменено.

### 2. Нативный парсер документа не знал поля каскада

`DurableDocument.java` отвергал `cascadeHealthOk`, `cascadeHealthPingMs`, `cascadeExitIpv6`,
`cascadeCheckedAt` как «unexpected key». Любой документ, записанный текущим Dart-слоем,
не проходил `policyReconcile`/`policyCommit`.

Исправление: четыре поля добавлены в optional-allowlist; они же добавлены в
`PolicyFixtures.document()`, чтобы нативные policy-тесты проходили на реальной форме документа.

### 3. Первый коннект после импорта шёл без плана

Документ уже содержал `connectionPolicy`, но in-memory флаг версионирования ещё не был
выставлен, поэтому `policyReceiptRequired` был false и `connect` уходил в легаси-путь
(`No saved connection plan`). После перезапуска флаг читался с диска и подключение работало.

Исправление: при доступной policy capability подключение всегда сначала согласует план, если
receipt ещё нет, независимо от in-memory флага.

### 4. Приоритет Android по умолчанию — AmneziaWG

Полный профиль начинал с Xray/REALITY; проверка HTTPS внутри нативного connect завершалась
`read/write on closed pipe`, после чего автоматический перебор терял согласованный план.
Для Android приоритет по умолчанию переведён на `awg` (нативный движок, проверен на этом
стенде). Автоматический fallback на RIVET/Xray сохранён; iOS и desktop значения не изменились.

## Подтверждение на сервере

```
interface: xioawg0
peer: ZrGj6rxgEtchISsdTtnWkVv6H5oO+UxYQP33cVpK0EM=
  endpoint: 85.198.104.255:6168
  allowed ips: 10.78.0.2/32, fd78:1::2/128
  latest handshake: 27 seconds ago
  transfer: 1.19 MiB received, 19.29 MiB sent

$ curl -fsS https://api.ipify.org
81.177.142.37
```

## Скриншоты

| Файл | Что видно |
|---|---|
| [`docs/screenshots/android-connected-20261117.png`](screenshots/android-connected-20261117.png) | Главная: «Отключиться», «Интерфейс активен», «Туннель активен · DNS через туннель», `Telefon KA`, AmneziaWG, счётчики |
| [`docs/screenshots/android-exit-ip-20261117.png`](screenshots/android-exit-ip-20261117.png) | Браузер телефона: `api.ipify.org` → `81.177.142.37` |

Снимки сделаны системным `screencap` после включения «Разрешить скриншоты» (по умолчанию
приложение ставит `FLAG_SECURE`, и кадр был бы чёрным).

## Проверки

| Прогон | Результат |
|---|---|
| `flutter test --no-pub` | **1138 passed, 23 skipped, 0 failed** |
| `flutter analyze` | 42 info/warning, 0 errors (прежний уровень) |
| Нативная компиляция policy-тестов | `:app:compileDebugUnitTestJavaWithJavac` — успешно |
| `flutter build apk --release --target-platform android-arm64` | успешно, 79.4 MB |
| Установка `adb install -r` поверх данных | успешно, профиль и согласованный план сохранились |
| Чистый импорт полного профиля → «Подключиться» | успешно, без перезапуска |

## Ограничения

- Проверен Android/arm64 и сервер 0.24.2; iOS, Windows и Linux-клиент в этом прогоне не
  пересобирались и не проверялись.
- Xray/REALITY на этом стенде не подтверждён: HTTPS-проверка внутри connect завершается
  закрытием канала. Поэтому Android по умолчанию идёт через AmneziaWG; Xray остаётся
  резервным кандидатом и требует отдельного разбора.
- Автоматический fallback после неудачного Xray может потерять policy receipt; это
  задокументировано как отдельный дефект и не маскируется. Проверенный путь — AWG-first.
