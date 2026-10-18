# Исходники и сборка XIO 0.18.0

Права на собственный код: GNU GPL version 3 only. Смотрите LICENSE и COPYRIGHT. Лицензии upstream сохраняются.

Комплект исходников включает собственный Dart/Kotlin/C++/Go код, изменённые forks Cloak/Tailscale/anet, AmneziaWG bridge, OpenVPN3 с зависимостями, pinned Go source ZIP в vendor/go-source-cache и Dart-пакеты в vendor/dart-sources. MANIFEST.json содержит хеши архивов. Зависимости хранятся с исходными именами и версиями; локальные replacements находятся в vendor. Для Xray используется Amnezia fork, не исходный upstream под другим тегом.

Среда: Flutter 3.47.7/Dart 3.13.5, Go1.27.2, JDK17, Android SDK36, NDK30.0.16248370, CMake/Ninja, Python3.12. SDK и стандартные системные инструменты устанавливаются отдельно. Сборка выполняется на Linux amd64; исходники не содержат приватного production/upload signing key. Для независимой сборки создайте свой ключ через tools/create-signing-key.py либо настройте собственную подпись.

1. Восстановите Go-кеш: `python3 tools/restore-go-sources.py --go /path/to/go1.27.2/bin/go`. Go проверяет зависимости по go.sum; исходные архивы сохранены рядом с манифестом. Для дополнительных build/test-only зависимостей, не входящих в snapshot исполняемого клиента, может потребоваться сеть.
2. Подготовьте gomobile по версии golang.org/x/mobile из protocol/rivet/go.mod.
3. Соберите runtime: `python3 tools/build-rivet.py --go /path/to/go --gomobile /path/to/gomobile`. Скрипт применяет совместимый CLOCK_BOOTTIME patch только к Android runtime. Изменений криптографии stdlib нет.
4. AmneziaWG: `python3 tools/build-amneziawg.py`. OpenVPN: `python3 tools/build-openvpn.py --help`, затем сборка для arm64-v8a, armeabi-v7a и x86_64. Параметры и pins входят в инструменты; сохраняйте реальные версии, не подменяйте архивы готовыми неизвестными библиотеками.
5. `python3 tools/package-server.py` создаёт сжатый серверный комплект и копирует принадлежащие XIO установочные скрипты в assets. Bootstrap ожидает gzip-поток.
6. Из app: `flutter pub get`, `flutter analyze`, `flutter test`, `flutter build apk --release --split-per-abi`, `flutter build appbundle --release`.
7. Проверьте подписи, launcher aliases, 16KiB alignment и реальные протоколы. Положите соответствующий source ZIP рядом с каждой поставкой бинарников, укажите однозначную ссылку на него. Не используйте абстрактную ссылку на ветку master вместо кода выпущенной версии.

Этот комплект исправляет обнаруженное отсутствие исходников используемых Go-компонентов; он не является независимым файловым аудитом всех лицензий SDK и системных библиотек. Для автономной воспроизводимой среды дополнительно зафиксируйте полный SDK/toolchain и Maven/pub caches. При новых движках или смене платформы обновите состав, notices и исходники.

Для HTTPS-совместимости Android8 включены четыре действующих публичных корня GTS/SSL.com из набора Mozilla/curl под MPL2.0, с сохранением проверки цепочки и имени сайта. Исходные блоки сертификатов, URL и проверенный хеш источника: app/assets/security/probe-roots.pem и vendor-metadata/probe-trust-roots.json. R2, отсутствующий в текущем наборе Mozilla, не добавляется. Системные сертификаты других приложений не меняются. При обновлении этой части повторите отрицательные TLS-тесты.
