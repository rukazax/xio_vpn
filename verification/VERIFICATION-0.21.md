# XIO 0.21 verification / Проверки XIO 0.21

- Flutter analysis clean; 105 tests passed, 5 conditional tests skipped. / Анализ чистый; 105 тестов пройдено, 5 условно пропущено.
- Actual release envelope verified against the pinned Ed25519 key; sizes and SHA-256 match platform packages. / Подпись, размеры и SHA-256 проверены на файлах выпуска.
- Three APKs: launcher aliases, signature and 16 KiB alignment passed; same publisher certificate as 0.20. / Три APK: ярлыки, подпись, выравнивание и прежний сертификат проверены.
- Android API35 emulator: replacement cleanup and persisted randomized job tested. / API35: очистка при замене и сохранённое случайное расписание проверены.
- Android API26: mocked GitHub responses plus private debug APK; real permission screen, installer confirmation, version replacement and package cleanup tested. Test fixtures are not published. / API26: локальный ответ GitHub и тестовый debug APK; настоящие разрешение, установщик, замена версии и очистка. Тестовые сборки не публикуются.
- Ubuntu isolated VM: APT installed missing EGL/GLES dependencies; GUI started as a regular user under Xvfb. / Ubuntu VM: APT установил EGL/GLES, интерфейс запущен обычным пользователем.
- Windows: explicit Windows kernel, seven helper capabilities and ZIP extraction checked under Wine. PowerShell syntax parsed; native Windows UAC, file replacement and Wintun remain untested. / Windows: ОС ядра, семь движков и ZIP проверены под Wine; синтаксис PowerShell проверен. Настоящие Windows/UAC/Wintun не проверены.
- Google Play AAB: external installation permission absent; store publication/moderation not tested. / AAB: разрешения внешней установки нет; публикация и модерация магазина не проверены.
- iOS: shared UI and native link/share source updated; no Mac/Xcode build or IPA. / iOS: обновлены исходники интерфейса и отправки ссылок; сборки Xcode и IPA нет.
- Protocol engines unchanged; this release does not establish a new cryptographic or DPI audit. / Движки протоколов не менялись; новый аудит криптографии или DPI не заявляется.

Machine-readable details: BUILD-INFO-0.21.json and update-021-*.json. / Подробности — в одноимённых JSON-файлах.
