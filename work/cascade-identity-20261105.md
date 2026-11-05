# XIO — строгие адреса и проверка именно выбранного каскада

Дата: 05.11.2026. Основа: `d48c921bf85b4145d86be96467a6112ab4ce4c6d`, ветка `fix/final-audit-20261105`.
Это отдельный проверенный этап исходного кода, **не выпуск, не merge в main и не подтверждение работающего VPS**. По решению владельца текущие целевые платформы — Android Full/Client, Ubuntu/Linux и Windows; macOS/iPhone отложены.

## Исправлено

- [Модель адресов](../app/lib/cascade_model.dart): literal IPv4/IPv6 exit, строгий SDK parser, единая каноническая IPv6-идентичность, скобки только для IPv6. Отвергаются malformed compression, зоны, URL, CIDR, host:port, старые числовые IPv4-алиасы и ведущие нули. DNS bridge ограничен 63 символами на метку; плохой IPv4 не проходит как DNS.
- [Выбор SSH-сервера](../app/lib/cascade_probe.dart): только единственное точное совпадение с SSH/VPN-host bridge. Нет совпадения или несколько записей — отказ, а не первый посторонний сохранённый VPS.
- [Привязка результата](../app/lib/cascade_health.dart): положительный/деградированный ответ должен подтвердить именно настроенный exit. Отсутствующий, malformed или другой exit не считается успехом. Уже отрицательная проверка сохраняет исходную причину. Egress parser не извлекает валидный префикс из malformed IPv6.
- [Экран](../app/lib/cascade_ui.dart): устаревший ответ предыдущей проверки не завершает новую проверку и не отменяет её таймер. Результат проверяется на идентичность exit до обновления статуса.
- [Регрессии](../app/test/cascade_identity_test.dart): 52 новых unit/widget cases, включая IPv4 round-trip через AppStore, атомарный отказ плохой замены, другой/неизвестный SSH target, дубликаты, неподтверждённый exit и гонку late response → retry → новый timeout. Новые сообщения добавлены во все 13 языковых каталогов, без ослабления l10n-гейтов.

## Проверки и доказательства

Debian 13, Flutter 3.47.7/Dart 3.13.5. Чистая основа из Git archive, затем overlay ровно 20 изменённых code/test/catalogue файлов. SHA256 всех 20 локальных файлов совпал с проверенным snapshot.

```text
snapshot: /srv/archives/snapshots/cascade-audit-20261105
logs:     /srv/archives/snapshots/cascade-audit-20261105/work/cascade-20261105
flutter analyze --no-pub                                  exit 0, 0 issues
flutter test --no-pub --reporter expanded --concurrency=1   exit 0, 419 passed / 8 skipped / 0 failed
cascade target suite (7 files)                            exit 0, 110 passed
l10n suite, все 13 языков и RTL/layout                    exit 0, 13 passed
Client-mode + identity regressions                       exit 0, 69 passed
```

Полный прогон включал `XIO_RELEASE_DIR=/srv/archives/releases/v0.24.2-audit`, `XIO_ASSET_AUDIT=1` и read-only по использованию symlink `snapshot/releases` на тот же реальный cache: это нужно старому hardcoded `../releases` гейту подписи/хешей. Реальные артефакты не заменены тестовыми. Восемь условных/live тестов остались skipped; это **не** физическая приёмка VPN/телефона/Windows.

Отрицательный контроль: отдельный snapshot с теми же исправленными библиотеками и тестами, но **только UI возвращён точной версией d48c921**. Три widget-регрессии (другой exit, отсутствующий exit, поздний старый успех во время retry) дают `0 passed / 3 failed`. В исправленном UI все три проходят. Родительский runner проверил ожидаемый failure и завершился exit 0; журналы сохранены.

Первоначальные сбои не скрыты: общий прогон выявил недостающие новые ключи локализации (исправлены все 13 каталогов); свежий snapshot первоначально пропустил legacy release gate из-за отсутствующего untracked cache (cache подключён, финальный прогон 419/8/0). В первом обработчике отрицательного контроля ошибочно ожидался `!`, тогда как Flutter печатает `Some tests failed.` — исправлено только утверждение формата результата, не тесты/продукт.

## Не закрыто этим этапом

IPv4 exit теперь корректно валидируется и сохраняется, **но это не означает готовый IPv4→IPv4 установщик или переключение native XIO traffic через контейнерный wg1**. Оба способа установки требуют полного проверенного payload, корректного backend/peering и привязки выдаваемых клиентских профилей. Этот участок выполняется отдельно. Live VPS не менялись; новые APK/DEB/Windows ZIP не собирались и не публиковались; на POCO ничего не устанавливалось. Подпись Windows/ограничения SAC не обходились. Общий XIO goal остаётся активным.
