# XIO changes / Изменения

## 0.22.3 — candidate / кандидат

IPv4/IPv6 endpoint selection, protected physical-network resolution, RIVET IPv6 payloads and reversible server recipe 23. RU/EN client UI. Physical Android and public IPv6 checks pending.

IPv4/IPv6 в endpoint, DNS через физическую сеть, IPv6-пакеты RIVET, обратимая ревизия сервера 23 и RU/EN в клиенте. Физический Android и публичный IPv6 ещё не проверены. См. docs/dualstack.

## 0.22.2 — 2026-10-23

- Отдельный Android-клиент для готовых серверов, общий главный экран, переключение серверов и раздельное туннелирование.
- Субклиенты с ограниченным API-доступом: серверная квота, отзыв своих клиентов, сохранение незавершённой операции.
- Root/admin SSH-ключи не экспортируются клиенту; серверная ревизия 21.
- Separate Android client for existing servers, shared home UI, server switching and split tunnelling.
- Scoped subclients: server-enforced quota, own-child revocation and durable pending operations.
- No root/admin SSH key export to clients; server recipe 21.
- Local checks passed; new client/live account API deployment and physical-device validation remain pending.

## 0.22.1 · 2026-10-21

- RU: Исправлена активация нового пользователя Cloak; серверный пакет — ревизия 20. Все пять протоколов отдельно проверены на физическом Android. [Отчёт](docs/verification/android-physical-2026-10-21.ru.md).
- EN: Fixed new Cloak user activation; server package revision 20. All five protocols individually checked on physical Android. [Report](docs/verification/android-physical-2026-10-21.en.md).

# XIO 0.21.0 — 2026-10-19

RU: GitHub и «Поделиться приложением» в «О XIO»; проверка обновлений в настройках приложения, пропуск отдельного релиза, случайное недельное расписание. Подпись Ed25519 и проверка SHA-256 перед установкой. Исправлена целевая ОС Windows в сборке через Wine; добавлена проверка запущенного ядра. Добавлены зависимости EGL/GLES для чистой Ubuntu. Системная установка Android/Ubuntu, обновление ZIP в Windows с резервной копией. Фоновая проверка метаданных Android. Сохранены платформенные ограничения iOS и Google Play.

EN: GitHub and Share app in About XIO; application update checks, skip-release choice and randomized weekly scheduling. Ed25519 manifest signature and package SHA-256 verification. Corrected the Windows kernel target for Wine packaging and added a runtime target check. Declared EGL/GLES dependencies for clean Ubuntu installations. Android/Ubuntu system installation, Windows ZIP replacement with backup. Android background metadata checks. iOS and Google Play distribution limits remain explicit.

[Блог / Blog](docs/blog/2026-10-19-updates.md) · [RU](docs/ru/updates.md) · [EN](docs/en/updates.md).

# Public launch — 2026-10-18

RU: Репозиторий открыт. Добавлены topics, Discussions и русская/английская публикации Telegraph. Код и версия приложения не менялись.

EN: Repository made public. Added topics, Discussions and Russian/English Telegraph introductions. Application code and version are unchanged.

[Блог / Blog](docs/blog/2026-10-18-public-launch.md).

# Documentation 1.0 — 2026-10-18

RU: Подробная двуязычная библиотека RIVET/H3 и RIVET/S1, схемы, графики, источники данных и эксплуатационные ограничения. Код приложения 0.20.0 не изменён.

EN: Detailed bilingual RIVET/H3 and RIVET/S1 library, diagrams, charts, evidence inputs and operational boundaries. Application 0.20.0 code is unchanged.

[Блог / Blog](docs/blog/2026-10-18-rivet.md).

# Changelog

## 0.22.0 — 2026-10-19

RU: удалены отдельные WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale; «Протоколы» перенесены в «Соединение». Добавлены раздача через VPN с root на Android и экспериментальная Windows ICS, миграция управляемого сервера с откатом, проверенный импорт XHTTP/VLESS Encryption и два исправления гонок Xray. Названия загрузок типовые. Переписаны RU/EN инструкции. [Статья](docs/blog/2026-10-19-restricted-networks.md).

EN: retired standalone WireGuard/OpenVPN/IKEv2/Shadowsocks/Tailscale; moved Protocols to Connection. Added rooted Android tethering and experimental Windows ICS, managed-server migration with rollback, checked XHTTP/VLESS Encryption import and two Xray race fixes. Generic download names and rewritten RU/EN guides. [Article](docs/blog/2026-10-19-restricted-networks.md#english).
 / История изменений

## 0.20.0

- Moved Help and FAQ, and Licence and responsibility into About XIO. / Справка, FAQ, лицензия и ответственность перенесены в «О XIO».
- Grouped engine information under Protocols. / Информация о движках собрана в подразделе «Протоколы».
- Moved Diagnostics and the session log into Connection settings. / Диагностика и журнал перенесены в настройки соединения.
- Added Russian and English repository documentation, navigation diagrams and release guidance. / Добавлены русская и английская документация, схемы навигации и инструкции по загрузке.

This update changes shared UI navigation. It does not add a new engine or establish additional security guarantees. / Обновление меняет общую навигацию. Новые движки и дополнительные гарантии безопасности не заявляются.

## 0.19.0

Ubuntu and Windows clients; iOS source integration. See [platform details](CROSS-PLATFORM-0.19.ru.md). / Клиенты Ubuntu и Windows, исходная интеграция iOS.

## 0.18.0

Android release, multi-engine client and distribution package. See [historical notes](history/README.0.18.0.ru.md). / Выпуск Android, клиент нескольких протоколов и комплект распространения.
