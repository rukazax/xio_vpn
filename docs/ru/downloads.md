# Скачать XIO

Единый принцип имён файлов:
`XIO-<Приложение>-<версия>-<ОС>-<архитектура>.<расширение>`
(`Client`/`Full` · `android`/`windows`/`ubuntu`/`ios` · `arm64-v8a`/`armeabi-v7a`/`x86_64`/`universal`/`x64`).

## XIO Client — подключение к готовым серверам

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.22.5-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-arm64-v8a.apk) | 22.8 МБ |
| Android 8+ · ARM32 | [XIO-Client-0.22.5-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-armeabi-v7a.apk) | 22.7 МБ |
| Android 8+ · x86-64 | [XIO-Client-0.22.5-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-x86_64.apk) | 24.0 МБ |
| Android 8+ · universal | [XIO-Client-0.22.5-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-universal.apk) | 66.7 МБ |
| Windows 11 x64 | [XIO-Client-0.22.5-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-windows-x64.zip) | 25.1 МБ |
| Ubuntu 22.04+ x64 | [XIO-Client-0.22.4-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-amd64.deb) | 0.22.4 |
| Ubuntu 22.04+ x64 | [XIO-Client-0.22.4-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-x64.tar.gz) | 0.22.4 |
| iOS | — | IPA нет |

## Полный XIO — свой сервер

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.22.5-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-arm64-v8a.apk) | 57.8 МБ |
| Android 8+ · ARM32 | [XIO-Full-0.22.5-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-armeabi-v7a.apk) | 57.8 МБ |
| Android 8+ · x86-64 | [XIO-Full-0.22.5-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-x86_64.apk) | 59.0 МБ |
| Android 8+ · universal | [XIO-Full-0.22.5-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-universal.apk) | 102.9 МБ |
| Windows 11 x64 | [XIO-Full-0.22.5-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-windows-x64.zip) | 60.2 МБ |
| Ubuntu 22.04+ x64 | [XIO-0.22.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.22.0/XIO-0.22.0-ubuntu-amd64.deb) | 0.22.0 |
| iOS | — | нет |

## Проверка и служебные файлы

- [SHA256SUMS-0.22.5.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/SHA256SUMS-0.22.5.txt) — контрольные суммы всех файлов 0.22.5
- [verification-0.22.5.json](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/verification-0.22.5.json) — отчёт проверки APK
- [source-inputs-0.22.5.json](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/source-inputs-0.22.5.json) — хеши исходных входов сборки

## Установка

- **Android:** разрешить установку из неизвестного источника для файлового менеджера, открыть APK.
  Клиент и полное приложение ставятся рядом (разные пакеты).
- **Windows:** распаковать ZIP целиком и запускать `XIOClient.exe` из папки (рядом нужны `data/` и
  `libexec/`). SmartScreen предупредит: приложение не подписано сертификатом издателя. Для
  подключения нужны права администратора — помощник меняет маршруты и DNS.
- **Ubuntu:** `sudo apt install ./XIO-Client-0.22.4-ubuntu-amd64.deb` либо распаковать tar.gz.
  Нужны `iproute2` и polkit.

[Все релизы](https://github.com/rukazax/xio_vpn/releases) · [Совместимость 0.22.5](../compatibility/0.22.5.ru.md) · [На главную](../../README.ru.md)
