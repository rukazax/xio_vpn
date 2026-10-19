# XIO 0.22: Xray compatibility patch / Исправление совместимости Xray

The Xray engine remains based on amnezia-vpn/amnezia-xray-core v1.260728.0, with two local synchronization fixes in `transport/internet/splithttp/client.go` and `dialer.go`. The modified files remain under MPL-2.0. Original authorship and license notices are retained. Full source is in `vendor/xray` in the corresponding source archive; a reproducible patch, license and hashes are in `patches/xray`.

Ядро Xray основано на amnezia-vpn/amnezia-xray-core v1.260728.0. Исправлены две гонки в `transport/internet/splithttp/client.go` и `dialer.go`. Изменённые файлы сохраняют MPL-2.0, сведения об авторах и исходные уведомления. Полный исходный код находится в `vendor/xray` архива исходников; воспроизводимый патч, лицензия и контрольные суммы — в `patches/xray`.

Own application code remains GPL-3.0-only. No new cryptographic primitive or upstream protocol is claimed as an XIO invention. Other dependencies retain their existing licenses; see the previous third-party notices.

The local Apache-2.0 amnezia-tun2socks copy removes optional proxy registrations from engine/register.go. Only XIO's protected adapter is registered; the original licence is included in vendor/tun2socks. Tailscale source retained in historical corresponding-source snapshots is not linked into 0.22 clients. / В локальной копии amnezia-tun2socks (Apache-2.0) удалена регистрация дополнительных прокси; сохранены исходная лицензия и уведомление об изменении.
