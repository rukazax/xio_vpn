# Загрузки XIO

> **v0.24.0 — текущий выпуск.** [Страница релиза](https://github.com/rukazax/xio_vpn/releases/tag/v0.24.0) и прямые ссылки ниже не зависят от `/latest`. Перед установкой прочитайте [ограничения](../compatibility/0.24.0.ru.md).

Одно правило имён файлов:
`XIO-<Приложение>-<версия>-<ОС>-<архитектура>.<формат>`

> **0.24.0 ставится поверх 0.23.1.** Имена пакетов и подпись не менялись, поэтому Android обновляет приложение и сохраняет профили и настройки.

## XIO Client — подключение к готовым серверам

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.24.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-arm64-v8a.apk) | 22.9 МиБ |
| Android 8+ · ARM32 | [XIO-Client-0.24.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-armeabi-v7a.apk) | 22.8 МиБ |
| Android 8+ · x86-64 | [XIO-Client-0.24.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-x86_64.apk) | 24.2 МиБ |
| Android 8+ · universal | [XIO-Client-0.24.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-universal.apk) | 67.0 МиБ |

iOS не собран: нужны Mac, Xcode и подпись Apple.

## Full XIO — свой сервер

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.24.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-arm64-v8a.apk) | 57.9 МиБ |
| Android 8+ · ARM32 | [XIO-Full-0.24.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-armeabi-v7a.apk) | 57.9 МиБ |
| Android 8+ · x86-64 | [XIO-Full-0.24.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-x86_64.apk) | 59.1 МиБ |
| Android 8+ · universal | [XIO-Full-0.24.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-universal.apk) | 103.1 МиБ |
| Ubuntu 22.04+ x64 | [XIO-Full-0.24.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-ubuntu-amd64.deb) | 49.0 МиБ, ставится через `apt` |
| Ubuntu 22.04+ x64 | [XIO-Full-0.24.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-ubuntu-x64.tar.gz) | 57.9 МиБ, переносимая сборка |
| Windows 11 x64 | [XIO-Full-0.24.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-windows-x64.zip) | ZIP: приложение, помощник, Wintun |
| Серверный архив | [xio-server-0.24.0.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/xio-server-0.24.0.tar.gz) | 21.3 МиБ, рецепт 25 |

> **Windows Client в 0.24.0 не входит.** Настольный клиент для Windows опубликован в 0.23.1.

## Что проверено в 0.24.0

- серверный архив — живая установка на Debian 13 (LXC, `fr-host.fr`), `init` ok, рецепт 25;
- XIO Full 0.24.0 на POCO X6 5G (Android 16): установка поверх 0.23.1, импорт профиля, подключение по RIVET/S1, отключение и повторное подключение;
- подпись и `zipalign` всех APK, сборка Windows и Ubuntu-пакетов.

Подробности и хэши — в `verification-0.24.0.json` на странице релиза.
