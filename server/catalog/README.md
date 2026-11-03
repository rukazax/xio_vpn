# Каталог «белых» SNI — `server/catalog`

Канонический генератор: `server/catalog/catalog.py`. Прежний `tools/whitelist-catalog.py`
удалён; второй реализации в дереве нет.

Назначение: список **точных FQDN**, пригодных как SNI входа XIO (Xray REALITY `serverName`/`dest`,
RIVET/S1), с измеренными свойствами и происхождением источника. Каталог не применяется
автоматически: выбор делает администратор.

Область — **только SNI-only**. При модели `ip+sni` каталог эффекта не даёт; это фиксируется
в отчёте, а не замалчивается.

## Файлы

| Файл | Назначение |
|---|---|
| `catalog.py` | генератор: разбор, пробы стадий 0–5, канонический хеш, атомарная запись, откат, подпись |
| `whitelist-pins.json` | **pin источника**: URL, ожидаемый `sha256`, коммит, лицензия. Меняется только отдельным ревьюируемым коммитом |
| `lint_catalog.py` | проверка готового артефакта (тот же `lint_document`, что в генераторе) |
| `tests/test_catalog.py` | герметичные тесты, критерии приёмки 1–7 |
| `xio-catalog.service`, `xio-catalog.timer` | еженедельный запуск, `Persistent=true`, `RandomizedDelaySec=30m` |

В git не кладутся: `whitelist-<YYYYMMDD>.json`, `whitelist-previous.json`,
`whitelist-state.json`, `*.sig`, `__pycache__/` — это рабочее состояние сервера (см. `.gitignore`).

## Формат артефакта

`whitelist-<YYYYMMDD>.json`, schema 1, UTF-8, LF, ключи сортированы, отступ 2:

```json
{
  "schema": 1,
  "contentSha256": "<sha256 канонического содержимого>",
  "source": {"url": "...", "commit": "<40 hex>", "sha256": "...", "license": "MIT",
             "fetchedAt": "...", "bytes": 15648, "lines": 910},
  "probe": {"performedOn": "<узел>", "interface": "eth0", "country": "FR",
            "bypassTunnel": true, "tlsRequires": "1.3", "probeMode": "tcp-tls13"},
  "counts": {"raw": 910, "unique": 910, "eligible": 0,
             "rejected": {"invalidEntry": 0, "unresolved": 0, "unreachable": 0,
                          "certInvalid": 0, "certMismatch": 0, "tls12Only": 0}},
  "entries": [{"fqdn": "example.ru", "eligible": true, "rejectReason": null,
               "resolved": ["203.0.113.10"], "tls13": true,
               "certSha256": "<sha256 DER>", "certNotAfter": "2027-01-01T00:00:00Z",
               "tlsRttMs": 42}]
}
```

`contentSha256` считается **только** по `(fqdn, eligible, sorted resolved)` в порядке сортировки
по `fqdn`. `tlsRttMs`, `certNotAfter`, `certSha256`, `fetchedAt` в него не входят: они меняются
между прогонами и не должны ломать детерминизм. Записи отсортированы по `fqdn`, повторов нет,
точка в конце FQDN запрещена, IDNA — A-label. У каждой записи `eligible: true` обязательны
`resolved`, `tls13: true`, `certSha256`, `certNotAfter`, `tlsRttMs` и `rejectReason: null`.

## Сборка

```sh
sudo python3 server/catalog/catalog.py build \
  --interface eth0 --country FR --node VPS-721137 \
  --out-dir /var/lib/xio-catalog --pins /var/lib/xio-catalog/whitelist-pins.json
```

Пробы идут **мимо туннеля**: сокет привязывается к физическому интерфейсу через
`SO_BINDTODEVICE`, поэтому `--interface` обязателен на сервере с активным туннелем. Точка
замера попадает в `probe.*`. Без `--interface` пробы меряют не ту сеть — такой прогон годится
только для отладки и в отчёт не идёт.

`--source-file` — офлайн-прогон по локальной копии источника. `--dry-run` печатает артефакт
в stdout и ничего не пишет.

## Коды выхода

| Код | Значение |
|---|---|
| 0 | ок |
| 2 | источник недоступен, артефакт не тронут |
| 3 | sha256 источника ≠ pin (или pin отсутствует), пустой/битый вход |
| 4 | пригодных меньше порога (`<10` или `<1 %` от `raw`), превышен бюджет времени, вход больше лимитов |
| 5 | ошибка записи/отката/подписи, артефакт не проходит lint |

Артефакт не меняется ни при одном коде, кроме 0: документ считается в памяти, запись —
последний шаг (`tmp` → `fsync` → `rename`), предыдущий файл сохраняется с его `sha256`
в `whitelist-state.json`.

## Pin источника

`whitelist-pins.json` меняется **только отдельным ревьюируемым коммитом**; таймер не имеет
права его править. Если фактический `sha256` источника не совпадает с pin — код 3, артефакт
не меняется. Если pin отсутствует — код 3 с сообщением `pin missing`.

## Проверка и откат

```sh
python3 server/catalog/lint_catalog.py server/catalog/whitelist-20261103.json
python3 server/catalog/catalog.py rollback --out-dir /var/lib/xio-catalog
```

Откат отказывается работать (код 5), если `sha256` предыдущего артефакта не совпадает
с манифестом.

## Тесты

Из корня репозитория:

```sh
python3 -m unittest discover -s server/catalog/tests -p "test_*.py" -v
python3 tools/test_catalog_determinism.py
```

Форма `-t .` не используется: в `server/catalog/` нет `__init__.py`, поэтому `discover -t .`
падает с `Start directory is not importable`. Тесты герметичны, сеть не используется, пробы
подменяются. Тест `kill -9` посреди записи выполняется только на Linux (нужны `SIGKILL`
и `flock`), на Windows он скипается.

`tools/test_catalog_determinism.py` проверяет детерминизм на фиксированном наборе проб:
одинаковые записи → побайтово одинаковый артефакт. Такой же тест есть в юнитах
(`test_same_probe_input_gives_byte_identical_artifact`), он же — доказательство критерия 1
в действующей формулировке.

**Поправка о детерминизме (в контракт).** Детерминизм гарантируется на **фиксированном входе
проб**: одинаковый набор probe-результатов даёт побайтово одинаковый артефакт. Живой прогон
недетерминирован по природе — таймауты, DNS и балансировка меняют `eligible`/`resolved` между
прогонами (наблюдалось 522 и 499 пригодных через минуту на одном хосте). Поэтому для живого
прогона фиксируются только: код 0, `contentSha256`, пересчитанный из `entries`, пройденный
порог и записанные `counts`. Требовать совпадения `contentSha256` двух живых прогонов нельзя —
это ловля флаки, а не регрессия.

## Подпись и доставка

`--sign-key` подписывает артефакт detach-подписью ed25519 (`<файл>.sig`), нужен пакет
`cryptography`. Отдача каталога через `client_api` и проверка подписи закреплённым ключом
в приложении — отдельный этап: нужен публичный ключ на клиенте.
