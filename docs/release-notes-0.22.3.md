# XIO / XIO Client 0.22.3+5012

RU: два Android-приложения с IPv4/IPv6 endpoint, переключением профилей и раздельным туннелированием. Полный XIO обслуживает VPS. Облегчённый клиент подключается к существующим серверам; субклиенты доступны только по серверной квоте и ограниченному HTTPS-токену. SSH/root/admin-ключи сервера в клиент не передаются.

На POCO X6 5G с Android 16/ARM64 и разрешённом IPv4 VPS на сборке 5011 проверены все пять протоколов обоих приложений: 20 независимых проверок HTTPS по имени/IP с подтверждённым адресом выхода. Проверены маршруты по приложениям/IP, обычный и ограниченный экспорт, создание субклиента, квота, отзыв и установка обновлений поверх прежних сборок. Версии каждого дополнительного сценария указаны в протоколе.

Исправлены IPv6 DNS для VPS без IPv6, права HTTPS-службы при строгом umask, выдача файлов Android через отдельные закрытые FileProvider и запуск Xray с раздельными маршрутами. Xray проверяет HTTPS через свой зашифрованный сеанс до TUN; проверка сертификата и свежего обмена сохранена. Серверная ревизия 24.

**Это тестовый релиз. Публичный IPv6 не проверен: на VPS нет IPv6-маршрута.** Локальные IPv6-пакеты и серверные правила проверены в изолированной сети. Один физический Android не означает проверку всех устройств. ARM32/x86-64 проверены как подписанные сборки. Root-раздача, деструктивное удаление VPS, автономность и нагрузка не проверялись. Защита снимков клиента FLAG_SECURE сохранена.

[Русский: описание, результаты, реальные снимки/превью и схемы](https://github.com/rukazax/xio_vpn/blob/main/docs/dualstack/0.22.3.ru.md) · [Клиент и субклиенты](https://github.com/rukazax/xio_vpn/blob/main/client/README.ru.md)

---

EN: two Android applications with IPv4/IPv6 endpoints, profile switching and split tunnelling. Full XIO maintains a VPS. Lightweight XIO Client connects to existing servers; subclients require a server-enforced quota and a restricted HTTPS token. Server SSH/root/admin keys are not passed to the client.

Both apps passed all five transports on build 5011 on a POCO X6 5G running Android 16/ARM64 and the authorized IPv4 VPS: 20 independent DNS/literal-IP HTTPS checks matched the expected exit. Additional versioned checks cover app/IP routing, ordinary/account/child export, child creation, quota, revocation and in-place upgrades.

Fixes address IPv6 DNS on IPv4-only servers, strict-umask HTTPS service permissions, Android file sharing with distinct non-exported FileProvider components, and Xray split-routing startup. Xray checks HTTPS through its encrypted session before exposing TUN; certificate and fresh-data checks remain enabled. Server recipe 24.

**Prerelease: public IPv6 remains unverified because the VPS has no IPv6 route.** Isolated local IPv6 packet and server-rule checks passed. One physical Android device does not establish universal compatibility. ARM32/x86-64 are build-verified. Rooted sharing, destructive VPS removal, battery life and load were not tested. Client FLAG_SECURE remains enabled.

[English guide, tests, screens and diagrams](https://github.com/rukazax/xio_vpn/blob/main/docs/dualstack/0.22.3.en.md) · [Client and subclient setup](https://github.com/rukazax/xio_vpn/blob/main/client/README.en.md)

Assets: full XIO ARM32/ARM64/x86-64; client ARM32/ARM64/x86-64/universal; full corresponding source with pinned dependency inputs; RU/EN documentation, screenshots/previews, diagrams and scoped evidence; SHA256SUMS. Desktop binaries are unchanged. Local suites: 113 Flutter passed/6 skipped, 13 client-mode passed, 31 server tests passed; overlapping suites. Go-race passed. APK signatures and 16-KB alignment verified.


Матрица пяти протоколов в обоих приложениях (20 HTTPS-проверок) выполнена на сборке 5011. В финальной 5012 нативное ядро/AAR не менялось: добавлены журналы жизненного цикла плитки без секретов. На 5012 отдельно проверены подключение/отключение основной кнопкой плитки, независимый HTTPS через VPN и контроль Xray в клиенте. Это не повтор всей матрицы на 5012.

The five-protocol matrix in both apps (20 HTTPS checks) ran on build 5011. Final build 5012 uses the unchanged native engine/AAR and adds secret-free tile lifecycle logs. Build5012 separately passed the tile primary connect/disconnect commands, independent VPN HTTPS and a client Xray control. This does not represent a rerun of the entire matrix on 5012.
