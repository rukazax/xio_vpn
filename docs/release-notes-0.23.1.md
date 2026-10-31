# XIO / XIO Client 0.23.1+5016

RU: проверка соединения больше не зависит от внешнего сайта. Туннель подтверждается свежим обменом, счётчиками трафика и DNS-запросом через туннель; опрос сайта стал необязательным и по умолчанию выключен (Настройки → «Проверять доступность сайта»). Так подключение проходит там, где сайт-пробник блокируется провайдером, а сам туннель работает.

Порядок выбора маршрута: сначала выбранный профиль, затем варианты того же endpoint с другим протоколом, затем остальные профили. Заблокированный протокол меняется раньше, чем точка входа, — адрес VPS при этом не теряется.

Добавлен живой контроль связи. Пока владелец хочет туннель, сторож раз в 15 секунд проверяет линию; при двух промахах подряд переподключается и повторяет попытки с паузой 5 секунд (первые три) и 15 секунд (дальше), пока сервер не вернётся. После восстановления счётчики продолжают расти. Проверено на POCO X6 5G (Android 16, ARM64): остановка входа приёмки → «Повторное подключение…» без провала в «Отключено», подъём входа → восстановление за 15 секунд, счётчики 24.3/19.8 КБ → 40.5/58.1 КБ.

Впервые проверен сквозной IPv6-payload. Сервер развёрнут на VPS-721137 с глобальным IPv6 `2a0c:b641:1a0:800::2a2` (TUN/TAP включён поддержкой провайдера), клиент получает внутри туннеля `fd79:1::fe/128`, `ping6` и `wget -6` проходят через туннель, ответ — глобальный адрес VPS (NAT66 на шлюзе). Внешний транспорт по глобальному IPv6 проверен отдельно: подключение к `[2a0c:b641:1a0:800::2a2]:18443` за 129–159 мс.

**Продакшен-выпуск.** Проверены один физический Android (POCO X6 — Client и Full, включая живое подключение через туннель и автопереподключение), Debian 13 и Windows x64 (запуск приложения); ARM32/x86-64 — подписанные сборки. Публичный IPv6 проверен на VPS с IPv6; у клиента в локальной сети глобального IPv6 нет, поэтому сквозной прогон шёл из network namespace на самом VPS. iOS не собирался.

[Русский: методика и критерии](https://github.com/rukazax/xio_vpn/blob/main/docs/compatibility/0.23.1.ru.md) · [Клиент и субклиенты](https://github.com/rukazax/xio_vpn/blob/main/client/README.ru.md)

---

EN: the connection check no longer depends on an external site. The tunnel is confirmed by a fresh exchange, traffic counters and a DNS lookup through the tunnel; the site probe is optional and off by default (Settings → "Check site availability"). This makes connecting work where the probe site is blocked by the ISP while the tunnel itself is fine.

Route selection order: the selected profile first, then same-endpoint variants with another protocol, then other profiles. A blocked protocol is switched before the entry point changes, so the VPS address is not lost.

A live link watchdog was added. While the owner wants the tunnel, the watchdog verifies the link every 15 seconds; after two consecutive misses it reconnects and keeps retrying with a 5 second pause (first three attempts) and 15 seconds afterwards until the server returns. After recovery the counters keep growing. Verified on a POCO X6 5G (Android 16, ARM64): stopping the acceptance entry → "Reconnecting…" without falling back to "Disconnected", starting it → recovery within 15 seconds, counters 24.3/19.8 KB → 40.5/58.1 KB.

End-to-end IPv6 payload was verified for the first time. The server runs on VPS-721137 with global IPv6 `2a0c:b641:1a0:800::2a2` (TUN/TAP enabled by the provider's support), the client receives `fd79:1::fe/128` inside the tunnel, `ping6` and `wget -6` pass through the tunnel, and the answer is the VPS global address (NAT66 on the gateway). IPv6 outer transport was verified separately: connecting to `[2a0c:b641:1a0:800::2a2]:18443` in 129–159 ms.

**Production release.** Verified on one physical Android (POCO X6 — Client and Full, including a live tunnel connection and auto-reconnect), Debian 13 and Windows x64 (application launch); ARM32/x86-64 are build-verified only. Public IPv6 was verified on a VPS that has IPv6; the client's LAN has no global IPv6, so the end-to-end run was executed from a network namespace on the VPS itself. iOS was not built.

[English methodology and criteria](https://github.com/rukazax/xio_vpn/blob/main/docs/compatibility/0.23.1.en.md) · [Client and subclient setup](https://github.com/rukazax/xio_vpn/blob/main/client/README.en.md)
