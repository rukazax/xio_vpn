# Проверка iOS без собственной среды Mac

XIO уже использует Flutter и нативное расширение `PacketTunnel` на `NEPacketTunnelProvider`. Переход на React Native/Expo не отменит эту системную часть и не нужен ради облачной сборки.

## Что выполняет workflow

`.github/workflows/ios-compile.yml` использует стандартный публичный runner `macos-15` с Xcode, Flutter 3.47.8 и Go из `protocol/rivet/go.mod`. Действия привязаны к проверенным коммитам. Нет секретов подписи, прав записи в репозиторий, публикации релиза или входа в Apple Account. Оплачиваемые runner и услуги не включаются. Небольшой артефакт содержит только журнал, версии, JSON результата и снимок; срок хранения — один день.

В Git отсутствует генерируемый ресурс `assets/xio-server.tar.gz`. `tools/restore-ios-ci-assets.py` извлекает ТОЛЬКО этот ресурс из уже выпущенного XIO-Full 0.23.0 Windows ZIP. Проверяются размер/закреплённый SHA-256 ZIP и SHA-256 самого ресурса из текущего `xio-server-release.json`; неизвестный существующий файл не перезаписывается. Полная распаковка ZIP и подмена ресурса пустой заглушкой не используются.

Проверки раздельны:
1. Модульные тесты Go-адаптера Apple, анализ и тесты Flutter.
2. `gomobile bind` создаёт настоящий XIORivet.xcframework для устройства и Simulator.
3. `flutter build ios --release --no-codesign` компилирует приложение и встроенный PacketTunnel; проверяется наличие обоих исполняемых файлов. Это НЕ подписанный IPA.
4. Отдельная отладочная сборка: загрузка свободного iPhone Simulator, установка/запуск приложения, наличие живого процесса после запуска и снимок экрана. Это проверка запуска интерфейса, НЕ работоспособности VPN-расширения на физическом iPhone.

`tooling/cross-platform/check-ios.sh` отказывается работать вне macOS с кодом 64. Он использует отдельный временный каталог, не меняет исходный Xcode-проект, не придумывает Developer Team ID и удаляет только свой временный каталог. Очистка выключает лишь выбранный им изначально выключенный Simulator. Общий срок ограничен workflow, загрузка Simulator — дополнительно 240 секундами.

## Что остаётся за пределами

Подпись и provisioning требуют настоящих разрешённых сертификатов/профилей: для приложения и расширения, Network Extension, app group и keychain groups. При их наличии подпись тоже можно автоматизировать на macOS CI; физический Mac рядом с Windows для этого не обязателен. Сертификаты, пароли и согласия владельца нельзя выдумывать.

Реальное подключение VPN, маршруты/DNS, переподключение и смена Wi-Fi/сотовой сети принимаются только отдельным тестом на iPhone. PWA не заменяет системный VPN. TCG VM на Dell остаётся отдельным экспериментом; успешная облачная проверка не означает, что в этой VM уже установлены macOS/Xcode/Simulator.

Подписанный путь сохранён без изменений: `build-ios.sh` использует согласованные `XIO_APPLE_TEAM_ID` и `XIO_IOS_EXPORT_OPTIONS`.

## Источники
- Flutter: https://docs.flutter.dev/deployment/ios
- Expo о Windows и собственном нативном коде: https://docs.expo.dev/faq/
- Apple TN3134 — требования к размещению Network Extension: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- Стандартные runner для публичных репозиториев: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
