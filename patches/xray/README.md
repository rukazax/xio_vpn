# XIO compatibility patch / Исправление совместимости XIO

Base: amnezia-vpn/amnezia-xray-core v1.260728.0. Original files retain their licenses.

2026-10-19: backport atomic reader publication and done.Instance close synchronization in transport/internet/splithttp/client.go, following the current XTLS implementation. Race-enabled XHTTP + TLS + VLESS Encryption loopback tests reproduced concurrent reads/writes in the original WaitReadCloser. Cryptographic algorithms are unchanged.

Основа: amnezia-vpn/amnezia-xray-core v1.260728.0. В WaitReadCloser перенесена синхронизация публикации HTTP-ответа и закрытия из текущей реализации XTLS. Исходная гонка воспроизведена локальными тестами с детектором гонок. Криптографические алгоритмы не изменялись.

Reference: https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/client.go

Also cache the upload buffer length before transferring its ownership to the HTTP writer in splithttp/dialer.go. This fixes a second race reproduced under repeated packet-up tests. / Также длина буфера сохраняется до передачи владения HTTP-писателю: устранена вторая гонка при повторных тестах packet-up.

XIO 0.22 also removes Shadowsocks/WireGuard JSON loader registration from infra/conf/xray.go and excludes their two loader source files from compilation. The dedicated XIO registry includes only supported protocols. Original MPL-2.0 files remain available as .go.disabled for corresponding-source provenance. / Также исключены загрузчики конфигурации Shadowsocks/WireGuard; их исходники сохранены с исходной лицензией.

## REALITY parser buffer (2026-11-17)

The pinned `github.com/xtls/reality` release parses the decoy target's first TLS
flight with an 8 KiB buffer (`size = 8192`). A decoy whose TLS `Certificate`
record is larger — `www.microsoft.com` now returns an 8273-byte record — makes
every REALITY handshake fail with `processed invalid connection …: handshake did
not complete successfully`, which looks like client authentication but is only a
target-size limit.

Fix: `vendor/reality` is that exact module with `size = 17 * 1024` (upstream's
current buffer), wired in through
`replace github.com/xtls/reality => ../../vendor/reality` in
`vendor/xray/go.mod` and `protocol/rivet/go.mod`. See `vendor/reality/XIO-CHANGES.md`.
No cryptographic or authentication logic is changed.
