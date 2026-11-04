# Аудит панели `server/webui` — 05.11.2026

Область: `server/webui/xio-webui.py` (1249 строк), `server/webui/index.html`,
`server/webui/xio-webui.service`, `server/webui/install-webui.sh`, `server/webui/README.md`.
Ветка `agent/p4` от `origin/main` (`fff525e`). Номера строк — по файлам после правки,
описанной в разделе «Исправлено сразу».

Метод: чтение кода по потоку запроса (TLS → маршрут → аутентификация → CSRF → действие),
сверка с заявленными в README/docstring свойствами, локальный прогон модуля в изолированном
каталоге (`py_compile`, создание токена, отсутствие секрета в неинтерактивном stdout).
Живой стенд не поднимался: Debian `192.168.88.17` в это время не отдаёт SSH-баннер
(порт 22 принимает TCP, ответа sshd нет), поэтому проверки «на железе» — в разделе
«Что не проверено».

## Что отдаётся без токена

| Путь | Ответ | Оценка |
|---|---|---|
| `GET /`, `GET /index.html` | статический `index.html` (20 635 Б) + CSP, без состояния | приемлемо: это только оболочка, данных в ней нет |
| `GET /api/health` | `{ok, app, version, time}` | низкий риск: версия и время сервера до аутентификации (fingerprinting) |
| `GET /api/state` | 401 + `WWW-Authenticate` | корректно: состояние требует аутентификации ( [`xio-webui.py:983`](../server/webui/xio-webui.py#L983) ) |
| `POST /api/service/*`, `/api/cascade/*`, `/api/user/*` | 401/403 до действия | корректно: [`xio-webui.py:1060`](../server/webui/xio-webui.py#L1060), [`xio-webui.py:1065`](../server/webui/xio-webui.py#L1065) |
| прочие `/api/*` | 404/405 | корректно |

Отдельно проверено, что тело запроса и query-строка не попадают в журнал: `log_message`
заглушён ( [`xio-webui.py:882`](../server/webui/xio-webui.py#L882) ), а свой `log()` пишет
только метод/путь/IP/статус ( [`xio-webui.py:92`](../server/webui/xio-webui.py#L92) ).
Единственное исключение до правки — см. находку P1 ниже.

## Находки

| # | Находка | Риск | Исправление |
|---|---|---|---|
| **P1** | **Токен панели печатался в stdout при первом старте** (было `xio-webui.py:135`: `sys.stdout.write("XIO WebUI token: %s\n" % raw)`). Юнит не переопределяет `StandardOutput`, значит stdout уходит в journald, и bearer-токен остаётся в `journalctl -u xio-webui` навсегда — читаемый всем, кто в группах `systemd-journal`/`adm`, в архивах журнала и в любом `journalctl -xe`, приложенном к отчёту об ошибке. Docstring при этом утверждал «секреты сюда не попадают никогда». | **P1, критично**: полный обход аутентификации по украденному журналу; секрет переживает перезапуск и ротацию логов | **Исправлено в ветке**: [`xio-webui.py:140`](../server/webui/xio-webui.py#L140) — токен печатается только при `sys.stdout.isatty()`, иначе выводится путь к файлу `0600`. Штатный путь установки не меняется: `install-webui.sh` читает `$DEST_DIR/token` ( [`install-webui.sh:75`](../server/webui/install-webui.sh#L75) ) |
| **P2** | **Нет таймаута чтения после TLS-хендшейка**: `tls.settimeout(None)` ( [`xio-webui.py:1192`](../server/webui/xio-webui.py#L1192) ), у `Handler` не задан `timeout`, `ThreadingHTTPServer` создаёт поток на соединение без ограничения ( [`xio-webui.py:1170`](../server/webui/xio-webui.py#L1170) ). Клиент, завершивший хендшейк и не отправивший запрос, держит поток вечно | **P2 (доступность)**: неаутентифицированный slowloris исчерпывает потоки/память | Предложено: `Handler.timeout = 60` (даёт `socket.timeout` в `handle_one_request` и закрытие) + ограничение числа одновременных соединений (семафор в `get_request`) |
| **P3** | **Ошибки `admin.py` отдаются клиенту дословно**: `_clip(res["err"] or res["out"], 600)` попадает в `error` ответа ( [`xio-webui.py:613`](../server/webui/xio-webui.py#L613) ) и в `warnings` состояния ( [`xio-webui.py:828`](../server/webui/xio-webui.py#L828) ). В stderr может оказаться traceback с путями, именами полей и фрагментами конфигурации `deployment.json` | P3: утечка внутренних деталей аутентифицированному клиенту (и в отчёты об ошибках) | Предложено: клиенту — `{"error":"admin.py failed","ref":"<8 hex>"}`, полный текст — только в `webui.log` с тем же `ref` |
| **P4** | **CSRF-токен статичен и выводится из bearer-токена, не привязан к сессии, не ротируется** ( [`xio-webui.py:134`](../server/webui/xio-webui.py#L134), отдаётся в состоянии [`xio-webui.py:839`](../server/webui/xio-webui.py#L839) ); `Origin`/`Referer` не проверяются вовсе | P3: при XSS/утечке состояния CSRF-защита не деградирует вместе с сессией; нет второго рубежа на случай отключённого `SameSite` | Сейчас риск снижен слоями: cookie `Secure; HttpOnly; SameSite=Strict` ( [`xio-webui.py:963`](../server/webui/xio-webui.py#L963) ), обязательный `Content-Type: application/json` ( [`xio-webui.py:1039`](../server/webui/xio-webui.py#L1039) ) и отсутствие CORS-заголовков. Предложено: CSRF-токен на сессию + ротация, проверка `Origin` для cookie-аутентифицированных POST с явным allowlist для обратного прокси |
| **P5** | **Rate-limit обходится и/или блокирует оператора**: счётчики per-IP в памяти ( [`xio-webui.py:951`](../server/webui/xio-webui.py#L951) ), теряются при рестарте, словари `_fails`/`_blocked` не ограничены и чистатся только при обращении того же IP. За рекомендованным обратным прокси все клиенты — `127.0.0.1` (README сам это признаёт), значит один атакующий блокирует вход оператору на 15 минут | P3: DoS на вход + рост памяти при переборе адресов IPv6 | Предложено: ограничить размер карт и чистить по таймеру; учитывать `X-Forwarded-For` только от доверенного прокси (`--trusted-proxy`) |
| **P6** | **Панель работает от root, и потомки наследуют широкий bounding set**, включая `CAP_SYS_ADMIN` и `CAP_SETUID` ( [`xio-webui.service:9`](../server/webui/xio-webui.service#L9), [`xio-webui.service:36`](../server/webui/xio-webui.service#L36) ). `ProtectSystem=full`, без `NoNewPrivileges` | P2: любая RCE в панели (stdlib HTTP-сервер + `subprocess` от root) равна root на хосте | Предложено: отдельный пользователь + узкий helper (polkit/`systemd-run`) для пяти разрешённых действий `systemctl`, либо `CapabilityBoundingSet` без `CAP_SYS_ADMIN` и `NoNewPrivileges=yes` для самой панели |
| **P7** | **Тело запроса читается и разбирается до аутентификации**: `do_POST` читает до 64 КиБ и парсит JSON ( [`xio-webui.py:1023`](../server/webui/xio-webui.py#L1023) ), `_authenticate()` — только на [`xio-webui.py:1060`](../server/webui/xio-webui.py#L1060) | P4: бесплатная работа для неаутентифицированного клиента; лимитер считает только неудачные аутентификации | Предложено: аутентификация по заголовкам до чтения тела (тело нужно только для действий) |
| **P8** | **`/api/health` без аутентификации и без лимита** ( [`xio-webui.py:977`](../server/webui/xio-webui.py#L977) ) | P4: версия приложения/панели для подбора эксплойтов, дешёвый liveness-зонд | Предложено: убрать `version` из публичного ответа либо требовать токен |
| **P9** | **Самоподписанный лист помечен как CA** (`basicConstraints critical CA:TRUE`) и живёт 3650 дней: openssl-ветка [`xio-webui.py:479`](../server/webui/xio-webui.py#L479), чистый Python [`xio-webui.py:416`](../server/webui/xio-webui.py#L416). HSTS `max-age=86400` на самоподписанном хосте ( [`xio-webui.py:900`](../server/webui/xio-webui.py#L900) ). `set_ciphers` задаёт только до-TLS1.3 набор ( [`xio-webui.py:1164`](../server/webui/xio-webui.py#L1164) ) | P4: клиент, доверившийся этому сертификату как CA, примет любой подписанный им лист; длинный HSTS на самоподписанном хосте даёт лишние блокировки | Предложено: `CA:FALSE`, срок 90–365 дней, `context.minimum_version = TLSv1_2` оставить, а список шифров не сужать вручную (TLS1.3 настройкой не покрывается); HSTS оставить только при реальном сертификате |
| **P10** | **CSP разрешает inline-скрипты**: `script-src 'unsafe-inline'` ( [`xio-webui.py:1008`](../server/webui/xio-webui.py#L1008) ) | P4: единственный рубеж против XSS — аккуратность шаблона. Проверено, что `index.html` экранирует всё через `esc()` ( [`index.html:220`](../server/webui/index.html#L220) ), инъекции сейчас нет | Предложено: вынести скрипт в отдельный файл или nonce/hash вместо `unsafe-inline` |
| **P11** | **Опрос состояния каждые 5 с = два процесса `admin.py`** (`status` + `inspect`, таймаут 20 с каждый) под глобальным `STATE_LOCK` ( [`xio-webui.py:990`](../server/webui/xio-webui.py#L990) ); кеш 2 с есть только у `systemctl` ( [`xio-webui.py:646`](../server/webui/xio-webui.py#L646) ) | P4: аутентифицированный клиент сериализует панель и нагружает хост | Предложено: кеш `build_state()` 3–5 с + single-flight вместо блокировки |
| **P12** | **`install-webui.sh` печатает токен и URL с `?token=`** в терминал ( [`install-webui.sh:97`](../server/webui/install-webui.sh#L97) ) | Инфо: токен попадает в транскрипты/скриншоты установки. Смягчено: страница вычищает `token` из адреса через `history.replaceState` ( [`index.html:486`](../server/webui/index.html#L486) ), сервер не логирует query | Оставить как есть, но не запускать установку через CI-лог; для аудита — `rm /opt/xio-webui/token && systemctl restart xio-webui` |
| **P13** | Права на секреты: каталог `0700`, `token` `0600` ( [`install-webui.sh:40`](../server/webui/install-webui.sh#L40), [`xio-webui.py:150`](../server/webui/xio-webui.py#L150) ), `UMask=0077` ( [`xio-webui.service:17`](../server/webui/xio-webui.service#L17) ), `webui.log` создаётся с `0600` ( [`xio-webui.py:102`](../server/webui/xio-webui.py#L102) ) | — | Замечаний нет. Ротации токена по расписанию нет: смена = удалить файл и перезапустить службу (сессии в памяти тоже сбрасываются) |
| **P14** | Сессии только в памяти, TTL 12 ч скользящий, cookie без префикса `__Host-` ( [`xio-webui.py:963`](../server/webui/xio-webui.py#L963) ) | Инфо: рестарт разлогинивает всех (это плюс), `__Host-` защитил бы от подмены cookie из дочернего домена | Предложено: `__Host-xio_sid` (требует `Path=/` и отсутствие `Domain` — уже так) |
| **P15** | Внешние команды: только списки аргументов, `shell=False`, `SAFE_ENV` ( [`xio-webui.py:564`](../server/webui/xio-webui.py#L564) ), юнит `systemctl` — из allowlist `X-XIO-Unit` ( [`xio-webui.py:1088`](../server/webui/xio-webui.py#L1088) ), имя пользователя — по `USER_RE` | — | Замечаний нет |
| **P16** | `install-webui.sh` подставляет `LISTEN` в юнит через `sed` ( [`install-webui.sh:48`](../server/webui/install-webui.sh#L48) ) | — | Замечаний нет: валидация `^[A-Za-z0-9.:-]+$` ( [`install-webui.sh:17`](../server/webui/install-webui.sh#L17) ) не пропускает `\n`, `=`, `/`, `|`, так что внедрить директиву в юнит нельзя |

## Исправлено сразу (P1)

`server/webui/xio-webui.py`:

```python
if created:
    log("token file created: %s" % self.path)
    # Секрет печатаем только в интерактивный терминал. Под systemd stdout
    # уходит в журнал, а журнал переживает установку...
    if sys.stdout.isatty():
        sys.stdout.write("XIO WebUI token: %s\n" % raw)
    else:
        sys.stdout.write(
            "XIO WebUI token written to %s (0600); read it with: cat %s\n"
            % (self.path, self.path))
    sys.stdout.flush()
```

Docstring модуля дополнен пунктом про журнал ( [`xio-webui.py:14`](../server/webui/xio-webui.py#L14) ).

Проверка: `python -m py_compile` — ok; модуль импортирован в пустом каталоге, токен создан,
в перехваченный (не-TTY) stdout попала только строка с путём, сам токен — нет:
`XIO WebUI token written to …/token (0600); read it with: cat …/token`.
`install-webui.sh` не менялся: он ждёт файл и печатает токен из него.

Остаточный риск P1: уже существующие установки, где токен был напечатан в журнал при первом
запуске, нужно считать скомпрометированными — токен там остался. Лечение: удалить файл токена
и перезапустить службу (`rm /opt/xio-webui/token && systemctl restart xio-webui`), затем
почистить журнал (`journalctl --vacuum-time=…` или `journalctl -u xio-webui --rotate`).

## Приоритет следующих правок

1. P2 (таймаут чтения) — 2 строки, снимает самый дешёвый способ уронить панель.
2. P6 (не root / узкий bounding set) — главный структурный риск.
3. P3 (не отдавать stderr `admin.py`), затем P4/P5.
4. P9–P11, P14 — гигиена.

## Что не проверено

* Живой стенд: TLS-хендшейк, поведение `journalctl` и права файлов на реальном хосте не
  проверялись — Debian был недоступен по SSH (порт 22 принимает TCP, sshd не отдаёт баннер),
  проверки выполнялись статически и на локальном запуске модуля. Права `0600`/`0700` на Linux
  выводятся из кода (`os.open(..., 0o600)`, `install -m`), но не подтверждены `stat` на сервере.
* Полный список того, что `admin.py status|inspect` печатает в stderr (для оценки P3), не
  собирался: это отдельный аудит `server/managed`.
* Нагрузочных проверок (slowloris, перебор IP для P5, стоимость `build_state`) не было.
* CSP/HTML-инъекции проверялись чтением `index.html` (экранирование `esc()`), без браузерного
  прогона и без CSP-репортов.
