# XIO compatibility patch / Исправление совместимости XIO

Base: amnezia-vpn/amnezia-xray-core v1.260728.0. Original files retain their licenses.

2026-10-19: backport atomic reader publication and done.Instance close synchronization in transport/internet/splithttp/client.go, following the current XTLS implementation. Race-enabled XHTTP + TLS + VLESS Encryption loopback tests reproduced concurrent reads/writes in the original WaitReadCloser. Cryptographic algorithms are unchanged.

Основа: amnezia-vpn/amnezia-xray-core v1.260728.0. В WaitReadCloser перенесена синхронизация публикации HTTP-ответа и закрытия из текущей реализации XTLS. Исходная гонка воспроизведена локальными тестами с детектором гонок. Криптографические алгоритмы не изменялись.

Reference: https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/client.go

Also cache the upload buffer length before transferring its ownership to the HTTP writer in splithttp/dialer.go. This fixes a second race reproduced under repeated packet-up tests. / Также длина буфера сохраняется до передачи владения HTTP-писателю: устранена вторая гонка при повторных тестах packet-up.

XIO 0.22 also removes Shadowsocks/WireGuard JSON loader registration from infra/conf/xray.go and excludes their two loader source files from compilation. The dedicated XIO registry includes only supported protocols. Original MPL-2.0 files remain available as .go.disabled for corresponding-source provenance. / Также исключены загрузчики конфигурации Shadowsocks/WireGuard; их исходники сохранены с исходной лицензией.
