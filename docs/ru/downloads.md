# Скачать XIO

Единый принцип имён файлов:
`XIO-<Приложение>-<версия>-<ОС>-<архитектура>.<расширение>`



> **0.23.0 ставится отдельным приложением.** Пакеты переименованы (`app.xio.client`, `app.xio.xio`), поэтому Android не обновит прежнюю сборку на месте: перенесите профили экспортом/импортом и удалите старую версию вручную. Старые профили `x1o://` по-прежнему импортируются.



> **0.23.0 СЃС‚Р°РІРёС‚СЃСЏ РѕС‚РґРµР»СЊРЅС‹Рј РїСЂРёР»РѕР¶РµРЅРёРµРј.** РџР°РєРµС‚С‹ РїРµСЂРµРёРјРµРЅРѕРІР°РЅС‹ (`app.xio.client`, `app.xio.xio`), РїРѕСЌС‚РѕРјСѓ Android РЅРµ РѕР±РЅРѕРІРёС‚ РїСЂРµР¶РЅСЋСЋ СЃР±РѕСЂРєСѓ РЅР° РјРµСЃС‚Рµ: РїРµСЂРµРЅРµСЃРёС‚Рµ РїСЂРѕС„РёР»Рё СЌРєСЃРїРѕСЂС‚РѕРј/РёРјРїРѕСЂС‚РѕРј Рё СѓРґР°Р»РёС‚Рµ СЃС‚Р°СЂСѓСЋ РІРµСЂСЃРёСЋ РІСЂСѓС‡РЅСѓСЋ. РЎС‚Р°СЂС‹Рµ РїСЂРѕС„РёР»Рё `x1o://` РїРѕ-РїСЂРµР¶РЅРµРјСѓ РёРјРїРѕСЂС‚РёСЂСѓСЋС‚СЃСЏ.

## XIO Client — подключение к готовым серверам

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-arm64-v8a.apk) | 22.8 МБ |
| Android 8+ · ARM32 | [XIO-Client-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-armeabi-v7a.apk) | 22.7 МБ |
| Android 8+ · x86-64 | [XIO-Client-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-x86_64.apk) | 24.0 МБ |
| Android 8+ · universal | [XIO-Client-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-universal.apk) | 66.7 МБ |
| Windows 11 x64 | [XIO-Client-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-windows-x64.zip) | 25.1 МБ |
| iOS | — | IPA нет |

## Полный XIO — свой сервер

| Система | Файл | Размер |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-arm64-v8a.apk) | 57.8 МБ |
| Android 8+ · ARM32 | [XIO-Full-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-armeabi-v7a.apk) | 57.8 МБ |
| Android 8+ · x86-64 | [XIO-Full-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-x86_64.apk) | 59.0 МБ |
| Android 8+ · universal | [XIO-Full-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-universal.apk) | 102.9 МБ |
| Windows 11 x64 | [XIO-Full-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-windows-x64.zip) | 60.2 МБ |
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
