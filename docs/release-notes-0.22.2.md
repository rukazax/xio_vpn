## Русский

XIO Client — отдельный облегчённый Android-клиент для готовых VPN-серверов. Владелец настраивает сервер в полном XIO, пользователь импортирует выданный профиль и подключается. Клиент устанавливается рядом с полной версией и не требует серверных root/admin SSH-ключей.

### Что добавлено

- Главный экран в оформлении основного приложения: большая кнопка подключения, состояние, сервер, протокол и счётчики трафика; светлая и тёмная темы.
- Переключение серверов и раздельное туннелирование по приложениям либо IP-сетям.
- Создание и отзыв своих субклиентов для аккаунтов с выданным правом и положительной квотой. Права, квота и принадлежность проверяются на сервере при каждой операции.
- Ограниченный HTTPS API вместо экспорта серверных SSH-ключей. Субклиент получает только собственные VPN-данные, без токена родителя и без права дальнейшего делегирования.
- Сохранение незавершённой операции: потеря ответа не запускает повторное создание с новым ID. Операция сверяется с тем же ID и ключами.
- Защита клиентского импорта и нативного хранилища от доступа к административным SSH-данным; ключи и токены на Android хранятся зашифрованными.

### Что скачать

| Файл | Назначение |
|---|---|
| `XIO-Client-0.22.2-arm64-v8a.apk` | Клиент для большинства современных телефонов, около 24 МБ |
| `XIO-Client-0.22.2-armeabi-v7a.apk` | Клиент для 32-битного ARM |
| `XIO-Client-0.22.2-x86_64.apk` | Клиент для x86-64 |
| `XIO-Client-0.22.2-universal.apk` | Все три поддерживаемые архитектуры, около 70 МБ |
| `XIO-0.22.2-android-arm64-v8a.apk` | Полное приложение владельца с выдачей нового доступа |
| `XIO-0.22.2-source.zip` | Исходники, нативные компоненты и зависимости для пересборки |
| `XIO-Client-0.22.2-docs-verification.zip` | Инструкции RU/EN, изображения и отчёты проверок |
| `SHA256SUMS-0.22.2.txt` | Контрольные суммы всех сборок и архивов |

Требуется Android 8.0+. Поддержка абсолютно всех Android-устройств не заявляется. Клиент содержит Xray, RIVET/S1, RIVET/H3, AmneziaWG и Cloak; отдельные WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale не возвращаются. Сборки для ПК остаются 0.22.0, подписанной iOS IPA нет.

### Как включить субклиентов

В полном приложении 0.22.2 отключите VPN, выберите пользователя с правом создавать клиентов и квотой, затем «Поделиться». Владелец подтверждает обновление серверной части до ревизии 21, включение отдельного HTTPS API на TCP 9444 и перевыпуск токена аккаунта. При необходимости разрешите порт в панели провайдера. Импортируйте новый профиль в XIO Client. Старый обычный VPN-профиль продолжает подключаться, но права создавать клиентов не получает. Старые SSH-пакеты администрирования клиент отвергает.

### Проверки и границы результата

`flutter analyze` без замечаний; 110 общих Flutter-тестов прошли, 5 пропущены; отдельно прошли 10 тестов клиентского режима и 26 серверных. Проверены квота, конкурентное создание, запрет повышения прав, отзыв чужого клиента, восстановление операции после потери ответа, закрепление TLS-сертификата и запрет перенаправления токена. APK прошли проверку подписи, состава и выравнивания ZIP/нативных библиотек; подпись клиента совпадает с предыдущей клиентской сборкой.

**Тестовый релиз:** новый клиент и API субклиентов не проверены на физическом Android и действующем VPS. Прежние испытания полной 0.22.1 не переносятся на новую функцию. Серверный API предварительный; до массового развёртывания нужны отдельная проверка установки, нагрузки и транспортного слоя. RIVET экспериментален; независимого криптоаудита и гарантий обхода любых блокировок нет.

[Инструкция](https://github.com/rukazax/xio_vpn/blob/v0.22.2/client/README.ru.md) · [Объяснение изменений](https://github.com/rukazax/xio_vpn/blob/v0.22.2/docs/blog/2026-10-23-client-0.22.2.ru.md)

<img src="https://raw.githubusercontent.com/rukazax/xio_vpn/v0.22.2/docs/images/client-home-light-0.22.2.png" width="270" alt="XIO Client: светлая тема"> <img src="https://raw.githubusercontent.com/rukazax/xio_vpn/v0.22.2/docs/images/client-home-dark-0.22.2.png" width="270" alt="XIO Client: тёмная тема">

*Локальные снимки интерфейса с вымышленными профилями; не физический телефон.*

---

## English

XIO Client is a separate lightweight Android app for existing VPN servers. The owner configures the server in full XIO; users import an issued profile and connect. The client installs alongside full XIO without receiving the server’s root/admin SSH keys.

### New functionality

- Home UI shared with the full app: large connection button, status, server selection, protocol, traffic counters, light/dark themes.
- Server switching and split tunnelling by application or IP network.
- Create/revoke own subclients for explicitly entitled accounts with a positive quota. Every operation checks live server rights, quota and ownership.
- Scoped HTTPS API instead of server SSH key export. Children receive only their own VPN credentials, without the parent token or further delegation rights.
- Durable pending operations: a lost response never automatically creates another child with a new ID. Reconciliation uses the original ID and keys.
- Client import/native storage guards reject administrative SSH data. Android stores credentials and account tokens encrypted.

Choose an architecture-specific `XIO-Client` APK or the universal client. `XIO-0.22.2-android-arm64-v8a.apk` is the full owner app. The source archive includes native source inputs and dependencies; a smaller documentation/verification ZIP and SHA-256 list are attached. Android 8.0+ is required; universal device compatibility is not claimed. Desktop builds remain at 0.22.0; no signed iOS IPA is provided.

Subclients require server recipe 21 and a newly issued account profile. In the full owner app 0.22.2, disconnect VPN, select an eligible user with quota and choose Share. The owner confirms the separate TCP 9444 API and account token rotation. Permit the port in the provider firewall if needed, then import the new profile into XIO Client. Ordinary VPN profiles continue connecting without this API and grant no subclient rights. Legacy SSH administration bundles are rejected by the client.

Local validation passed: clean analysis; 110 general Flutter tests, 5 skips; separately 10 client-mode and 26 server tests; APK signatures, assets and ZIP/native alignment. Tests cover live quota, concurrency, privilege-escalation and ownership rejection, timeout reconciliation, certificate pinning and redirect rejection.

**Prerelease:** the new client and account API have not been validated on physical Android or a live VPS. Earlier full-app 0.22.1 tests do not establish that result. The preliminary API needs installation/load validation and production transport review before mass deployment. RIVET remains experimental, without an independent cryptographic audit or universal blocking-resistance claims.

[Setup and limits](https://github.com/rukazax/xio_vpn/blob/v0.22.2/client/README.en.md) · [Design and changes](https://github.com/rukazax/xio_vpn/blob/v0.22.2/docs/blog/2026-10-23-client-0.22.2.en.md)
