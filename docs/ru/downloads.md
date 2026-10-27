# Скачать XIO

> **v0.23.0 — предварительный выпуск.** [Страница выпуска](https://github.com/rukazax/xio_vpn/releases/tag/v0.23.0) и прямые ссылки ниже доступны без `/latest`. Перед установкой проверьте [ограничения](../compatibility/0.23.0.ru.md).

Единый принцип имён файлов:
`XIO-<Приложение>-<версия>-<ОС>-<архитектура>.<расширение>`

> **0.23.0 ставится отдельным приложением.** Пакеты переименованы (`app.xio.client`, `app.xio.xio`), поэтому Android не обновит прежнюю сборку на месте: перенесите профили экспортом/импортом и удалите старую версию вручную. Старые профили `x1o://` по-прежнему импортируются.

## XIO Client — подключение к готовым серверам

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-arm64-v8a.apk) | 22.9 МиБ |
| Android 8+ · ARM32 | [XIO-Client-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-armeabi-v7a.apk) | 22.7 МиБ |
| Android 8+ · x86-64 | [XIO-Client-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-x86_64.apk) | 24.1 МиБ |
| Android 8+ · universal | [XIO-Client-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-universal.apk) | 66.8 МиБ |
| Windows 11 x64 | [XIO-Client-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-windows-x64.zip) | 25.1 МиБ |
| Ubuntu 22.04+ x64 | [XIO-Client-0.23.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-ubuntu-amd64.deb) | 16.7 МиБ |
| Ubuntu 22.04+ x64 | [XIO-Client-0.23.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-ubuntu-x64.tar.gz) | 22.7 МиБ |
| iOS | — | IPA нет |

## Полный XIO — свой сервер

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-arm64-v8a.apk) | 57.8 МиБ |
| Android 8+ · ARM32 | [XIO-Full-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-armeabi-v7a.apk) | 57.8 МиБ |
| Android 8+ · x86-64 | [XIO-Full-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-x86_64.apk) | 59.1 МиБ |
| Android 8+ · universal | [XIO-Full-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-universal.apk) | 102.9 МиБ |
| Windows 11 x64 | [XIO-Full-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-windows-x64.zip) | 60.2 МиБ |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-ubuntu-x64.tar.gz) | 57.5 МиБ |
| iOS | — | нет |

## Проверка и служебные файлы

- [SHA256SUMS-0.23.0.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/SHA256SUMS-0.23.0.txt) — контрольные суммы всех файлов 0.23.0
- [verification-0.23.0.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/verification-0.23.0.json) — отчёт проверки APK
- [source-inputs-0.23.0.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/source-inputs-0.23.0.json) — хеши исходных входов сборки

## Установка

- **Android:** разрешить установку из неизвестного источника для файлового менеджера, открыть APK.
  Клиент и полное приложение ставятся рядом (разные пакеты).
- **Windows:** распаковать ZIP целиком и запускать `XIOClient.exe` из папки (рядом нужны `data/` и
  `libexec/`). SmartScreen предупредит: приложение не подписано сертификатом издателя. Для
  подключения нужны права администратора — помощник меняет маршруты и DNS.
  Нужны `iproute2` и polkit.

[Все релизы](https://github.com/rukazax/xio_vpn/releases) · [Совместимость 0.23.0](../compatibility/0.23.0.ru.md) · [На главную](../../README.ru.md)
