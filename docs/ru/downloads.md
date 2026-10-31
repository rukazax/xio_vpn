# Скачать XIO

> **v0.23.1 — текущий выпуск.** [Страница выпуска](https://github.com/rukazax/xio_vpn/releases/tag/v0.23.1) и прямые ссылки ниже доступны без `/latest`. Перед установкой проверьте [ограничения](../compatibility/0.23.1.ru.md).

Единый принцип имён файлов:
`XIO-<Приложение>-<версия>-<ОС>-<архитектура>.<расширение>`

> **0.23.1 ставится поверх 0.23.0.** Имена пакетов не менялись, Android обновляет приложение и сохраняет профили и настройки.

## XIO Client — подключение к готовым серверам

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.1-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-arm64-v8a.apk) | 22.9 МиБ |
| Android 8+ · ARM32 | [XIO-Client-0.23.1-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-armeabi-v7a.apk) | 22.8 МиБ |
| Android 8+ · x86-64 | [XIO-Client-0.23.1-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-x86_64.apk) | 24.2 МиБ |
| Android 8+ · universal | [XIO-Client-0.23.1-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-universal.apk) | 67.0 МиБ |

iOS не собран: нужен Mac, Xcode и подпись Apple.

## Full XIO — свой сервер

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.1-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-arm64-v8a.apk) | 57.9 МиБ |
| Android 8+ · ARM32 | [XIO-Full-0.23.1-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-armeabi-v7a.apk) | 57.9 МиБ |
| Android 8+ · x86-64 | [XIO-Full-0.23.1-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-x86_64.apk) | 59.2 МиБ |
| Android 8+ · universal | [XIO-Full-0.23.1-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-universal.apk) | 103.1 МиБ |
| Windows 11 x64 | [XIO-Full-0.23.1-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-windows-x64.zip) | ZIP: приложение, помощник, Wintun |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.1-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-ubuntu-amd64.deb) | 49.1 МиБ |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.1-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-ubuntu-x64.tar.gz) | 57.9 МиБ |
| Серверный пакет | [xio-server-0.23.1.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/xio-server-0.23.1.tar.gz) | 21.3 МиБ, серверная часть для Linux-хоста |

Ubuntu-пакеты входят в 0.23.1: `.deb` ставится через `apt`, `.tar.gz` распаковывается.

> **Известный дефект 0.23.1.** Серверный пакет внутри полных сборок падает при установке на правиле
> `POSTROUTING` (`iptables: Can't use -i with POSTROUTING`); на хостах только с IPv6 дополнительно
> падает таймер статистики с `Command failed: wg`. Исправлено коммитом `19d55dc`, войдёт в следующую
> сборку. На работу клиента с RIVET и AWG это не влияет.

## Проверка файлов

- [SHA256SUMS-0.23.1.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/SHA256SUMS-0.23.1.txt) — контрольные суммы всех файлов 0.23.1
- [verification-0.23.1.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/verification-0.23.1.json) — отчёт проверки сборок
- [release-notes-0.23.1.md](https://github.com/rukazax/xio_vpn/blob/main/docs/release-notes-0.23.1.md) — что изменилось

Проверить локально: `sha256sum -c SHA256SUMS-0.23.1.txt` (Linux/macOS) или `Get-FileHash <файл> -Algorithm SHA256` (Windows).

## Установка

- **Android:** откройте APK; Android 8+ спросит разрешение на установку из этого источника. Обновление ставится поверх 0.23.0 с сохранением профилей.
- **Windows:** распакуйте ZIP и запустите `XIO.exe`. Помощник (`libexec\xio-tunnel.exe`) запускается с правами администратора — это нужно для создания сетевого интерфейса.
- Проверка соединения в 0.23.1 не требует внешнего сайта: туннель подтверждается свежим обменом, счётчиками и DNS через туннель. Опрос сайта включается отдельно в настройках.

[Все релизы](https://github.com/rukazax/xio_vpn/releases) · [Совместимость 0.23.1](../compatibility/0.23.1.ru.md) · [На главную](../../README.ru.md)
