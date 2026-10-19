# Сборка из исходников

[English](../en/build.md) · [Главная](../../README.ru.md)

Скачайте соответствующий версии архив исходников на [странице загрузок](downloads.md). Он содержит полный код, изменённые сторонние компоненты и зафиксированные исходники зависимостей. SDK, production-ключи подписи и приватные профили в комплект не входят. При сборке из Git используйте исходники vendor той же версии; не заменяйте изменённые forks произвольным upstream.

Среда текущего проекта: Flutter 3.47.7, Dart 3.13.5, Go 1.27.2, Python 3.12; Android — JDK 17, SDK 36, NDK 30.0.16248370, CMake/Ninja. Не обновляйте зависимости автоматически перед воспроизведением выпуска.

```sh
cd app
flutter pub get
flutter analyze
flutter test
```

## Android

Восстановите Go-кеш и соберите нативные движки инструментами `tools/restore-go-sources.py`, `tools/build-rivet.py`, `tools/build-amneziawg.py` и `tools/build-openvpn.py`. Точные параметры доступны через `--help`. Затем `python3 tools/package-server.py`. Полная инструкция по происхождению исходников и ограничениям автономной сборки: [SOURCE-BUILD.ru.md](../../legal/SOURCE-BUILD.ru.md).

Настройте свой ключ подписи через `tools/create-signing-key.py` или собственную конфигурацию. Чужой ключ не нужен и не публикуется. Из `app/`:

```sh
flutter build apk --release --split-per-abi
flutter build appbundle --release
```

Для APK выполните `tools/check-android-launcher.py`, `tools/check-native-payload.py`, `apksigner verify` и `zipalign -c -P 16 4`. Подпись собственным ключом не позволяет обновить установленный пакет, подписанный другим издателем, без отдельной процедуры миграции.

## Ubuntu

Установите Flutter Linux build dependencies, GTK3 development libraries, CMake/Ninja, Go. Выполните `tools/build-linux.sh`. Для запуска VPN нужны iproute2 и polkit. Интерфейс запускается без root, сетевой помощник — отдельно с системным подтверждением.

## Windows

Собирайте на Windows с Flutter, Go и Visual Studio с C++ desktop workload. Выполните `tools/build-windows.ps1`. В комплект должны входить `data/`, `libexec/xio-tunnel.exe`, официальная `wintun.dll` и её лицензия. Верификация Wine не заменяет проверку драйвера, UAC, маршрутов и DNS на Windows.

## iOS

Нужны Mac/Xcode, iOS SDK, ваша команда Apple Developer и подходящая регистрация NetworkExtension. Настройте App IDs, app group, keychain group и provisioning. Затем задайте `XIO_APPLE_TEAM_ID`, `XIO_IOS_EXPORT_OPTIONS` и выполните `tooling/cross-platform/build-ios.sh`. Не помещайте сертификаты и provisioning-секреты в репозиторий. Исходная интеграция iOS поддерживает только RIVET/H3 и S1 и требует реального тестирования.

[Лицензия](../../LICENSE) · [Условия компонентов](../../THIRD-PARTY-NOTICES.md) · [Помощь разработчикам](../../CONTRIBUTING.md)


Нативный Android runtime сохранён из 0.18. Для его точной пересборки используйте `native-sources/android-runtime-0.18` из полного исходного архива и README этого каталога. [Происхождение исходников](../native-source-provenance.md).


## Сборка Windows AOT на Linux

Не используйте ядро Dart, собранное для Android или Linux: имя ОС фиксируется при генерации kernel. Для упаковки через Wine предусмотрен `tooling/cross-platform/build-windows-on-linux.py`. Он требует готовый Windows runner и Windows gen_snapshot той же версии Flutter, проверяет `Platform.isWindows`, доступность семи движков и распаковку ZIP в запущенном Windows-ядре. Затем отдельно компилирует `lib/main.dart` с `--target-platform=windows-x64`.

```sh
python3 tooling/cross-platform/build-windows-on-linux.py --runner ПУТЬ_К_BUNDLE --gen-snapshot ПУТЬ_К_GEN_SNAPSHOT_EXE --wine-prefix ПУТЬ_К_WINE_PREFIX
```

Это не заменяет нативную проверку Windows: Wintun, UAC и PowerShell-замена файлов требуют настоящей Windows. Основной поддерживаемый способ сборки — `tools/build-windows.ps1` на Windows.
