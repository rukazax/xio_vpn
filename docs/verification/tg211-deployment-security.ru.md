# XIO VPN — аудит установки и протоколов (TG211)

Дата: 31.10.2026, 01:53–03:00 MSK. Задача: TG211, XIO VPN only (не x1o).
Канонический dirty-репозиторий: `C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit`,
HEAD `689ac18e9978bea20205763b85263181e0ef264e`, рабочее дерево содержит незакоммиченные изменения
других исполнителей. Аудит read-only; production-файлы не редактировались.

## 1. Итог

- **P0 (release blocker), воспроизведён:** в `app/assets` лежит legacy-сборка сервера с путями `x1o`,
  recipe 24, тогда как исходники `server/managed` — recipe 25 и пути `xio`. Проверка SHA256 в приложении
  проходит, потому что манифест и архив согласованы между собой, но оба устарели. Свежая установка из
  текущего бандла не может быть принята как установка аудированного кода; вероятен отказ установки.
- **P2, воспроизведён:** client API сохраняет полный ответ создания пользователя, включая одноразовые
  private key/tls-crypt-v2/IKE-пароль/Tailscale auth key, в `deployment.json` под
  `clientApiOperations[...].response.configs`. Это противоречит заявлению «no client private keys» и
  расширяет последствия копирования/бэкапа `/etc`.
- **P3, воспроизведён:** в restricted-режиме (значение по умолчанию при `init`) остаётся запущенным
  plain WireGuard `xio0` и открывается UDP 51820, хотя `public` скрывает `wireguard` и `render` не
  добавляет peer'ов. Это лишняя attack surface/деанонимизация restricted-профиля.
- **P3, source review:** правила FORWARD/MASQUERADE для OpenVPN-подсетей в `network_stack.firewall`
  не ограничены входным интерфейсом (`-i`), включая subnet `10.82.0.0/24` без TUN. На общем хосте это
  позволяет локальному процессу/контейнеру с CAP_NET_RAW использовать NAT при source spoofing.
- **Обход аутентификации/admin-эскалация уровня P1 не найден.** Проверенные границы admin/client API, обновление, Xray,
  OpenVPN/Cloak, AWG и physical DNS/kill-switch в пределах локальных тестов — PASS (см. раздел 5).
  Это не независимая сертификация безопасности.

## 2. Что именно проверялось

Аудит исходников и локальные тесты: Python 3.10 (Windows, только тестовые shims для `fcntl/pwd/
socketserver`), GNU tar 1.35 в WSL, Go 1.27.3 windows/amd64 (task-local toolchain; `go.mod`
минимум 1.27.3 после parent patch). Не выполнялись SSH/VPS-команды, не
менялись host network/TUN/firewall/device, не использовались секреты, не запускались CI/публикации.
`govulncheck` не дублировался: его ведёт parent.

Проверенные области: `server/managed/{admin,client_api,stack,network_stack,update,bootstrap,
rivet-setup}.py|sh`, `tools/package-server.py`, `app/lib/managed_service.dart` (read-only, зона другого
исполнителя), `protocol/rivet/internal/{physical,awgactivation,xrayclient,desktop,xiofirewall}`,
`protocol/rivet/mobile/awg*`, существующие тесты и `docs/verification`.

## 3. Фактически поддерживаемые транспорты

По коду, а не по README:

| Транспорт | Порт/условие | Аутентификация/состояние |
|---|---|---|
| WireGuard (`xio0`) | UDP 51820 | peer public keys; в restricted peers не рендерятся, но listener/порт остаются |
| AmneziaWG (`xioawg0`) | UDP 51821 | обфускация Jc/Jmin/Jmax/S1/S2/H1–H4; peer keys |
| Xray VLESS Reality | TCP 4443 | UUID + Reality public key/shortId; TLS 1.3/Reality |
| Shadowsocks 2022 | TCP/UDP 8388 | только non-restricted; отключён в restricted |
| OpenVPN UDP | UDP 1194 | client cert + tls-crypt-v2 + CRL; direct только non-restricted |
| OpenVPN TCP | TCP 1195 на 127.0.0.1 | cert/tls-crypt-v2; снаружи только через Cloak |
| Cloak | TCP 9443 | per-user UID (base64 16 байт), проксирует OpenVPN TCP |
| IKEv2 | UDP 500/4500 | EAP-MSCHAPv2 + server cert; только non-restricted |
| RIVET H3/S1 | TCP/UDP 8443 (см. rivet-setup) | отдельная реализация; зона другого исполнителя, не сертифицирована здесь |
| Headscale/Tailscale mesh | TCP 18443, UDP 3478/41641 | optional; pinned binaries, preauth keys |
| Client API | TCP 9444 HTTPS | Bearer token (SHA256 at rest), self-signed cert + SHA256 pin |

Restricted default: `awg`, `xray`, `cloak`, `rivet-h3/s1`; `public` скрывает wireguard/SS/OpenVPN
direct/IKE, но см. F3.

## 4. Findings

### F1 — P0: packaged server asset — legacy `x1o`/recipe 24, не аудированный source recipe 25

**Evidence.**
- `app/assets/xio-server-release.json`: `recipeVersion=24`, `sha256=b5b44f72934036ffbad469fdd31fb0142726995259a91bbbdeadedb590752247`.
- `server/managed/admin.py:15` и `update.py:26`: `RECIPE=25`; `tools/package-server.py:15`: recipe 25.
- Архив `app/assets/xio-server.tar.gz`: 22 314 372 байта, SHA256 `b5b44f...` (манифест совпадает).
- В архиве `admin.py` содержит `ROOT=Path('/etc/x1o-managed')` и `LIB=Path('/usr/local/lib/x1o-managed')`
  (59 вхождений `x1o`); `stack.py`, `network_stack.py`, `dualstack.py`, `rivet-setup.py` также
  используют `x1o`. Исходники — `xio`, 0 вхождений `x1o`.
- `app/assets/xio-bootstrap.sh` (`86dc8128...`) ожидает `lib=/usr/local/lib/xio-managed`;
  `app/assets/xio-server-update.py` (`c66ec61d...`) — recipe 24. Исходные `bootstrap.sh`
  (`4f115394...`) и `update.py` (`fc9f7e6c...`) — recipe 25 и новее.
- Приложение проверяет хэш архива: `app/lib/managed_service.dart:297-303` (`ServerRelease.load`,
  `verifyArchive`) — это **PASS**, но проверяется устаревший архив по устаревшему манифесту.
- Нормализованные SHA256 исходников из архива против source: admin `d2801a93…`/`2e70ee61…`,
  client_api `db7d1381…`/`b8e69f8b…`, stack `ab0fbed3…`/`9bc43aee…`, network_stack `55f8134f…`/
  `40e09c55…`, dualstack `52586fcb…`/`a6507357…`, rivet-setup `137aa828…`/`1293b1aa…`.

**Impact.** Bootstrap раскладывает файлы в `/usr/local/lib/xio-managed`, а legacy `admin.py` ищет
`LIB=/usr/local/lib/x1o-managed`; по коду `admin.init` → `rivet_install` должен упасть на
`LIB/'rivet'` (missing), а `stack.install` — на `LIB/'xraygateway'`. Фактический live-запуск без VPS не
выполнялся; это P0 из-за несоответствия и неаудированности артефакта, а не подтверждённый live-отказ.
Даже частично установленный сервер будет legacy-кодом без текущих исправлений (IPv6/rollback/
валидация). SHA256-проверка не обнаруживает drift, потому что manifest и tar стары, но согласованы.

**Exact minimal fix.** Пересобрать `app/assets` только из source при наличии pinned `vendor-server`
(владелец сборки): `python tools/package-server.py --check`, затем без `--check`; проверить
`recipeVersion=25`, hash и отсутствие `x1o`; выполнить свежую изолированную установку parent'ом.
Добавить release-gate: тест `tests/test_release_artifact_consistency.py` (падает на текущем дереве,
должен проходить после пересборки). Не выпускать APK/EXE с текущими assets.

**Regression.** `tests/test_release_artifact_consistency.py`: 5 тестов, 10 subtest-падений;
`evidence/release-artifact-tests.log`; summary `evidence/packaged-vs-source-summary.txt`.

### F2 — P2: client API сохраняет одноразовые private key в `deployment.json`

**Evidence.** `server/managed/client_api.py:169-175`: `response` включает `configs` из
`result.get('configs', {})`, затем `state='complete', response=response` сохраняется в
`deployment.json`. `stack.create` возвращает OpenVPN config с `<key>`/`<tls-crypt-v2>`, IKE-пароль,
Cloak UID, Tailscale authKey. `admin.py` docstring: «no client private keys». Файл `deployment.json`
имеет 0600 root, но попадает в бэкапы/копии `/etc`; ответ хранится бессрочно до revoke
(`admin.py` удаляет `response` только для revoke-целей).

**Impact.** Секреты клиентов доступны любому, кто получит копию deployment.json (бэкап, snapshot,
ошибочный export), дольше, чем нужно для доставки профиля. Это расширяет blast radius при компрометации
бэкапа; root-компрометация сервера и так даёт многое, поэтому не P0.

**Exact minimal fix.** Не сохранять `configs` в durable operation response: хранить только
`user.id/slot` и несекретный `server`; для replay возвращать `state=complete` без секретов и требовать
owner reconciliation при потерянном ответе. Если нужен replay профиля — шифровать `configs` отдельным
root-only ключом (`/etc/xio-managed/operation.key`, 0600) и удалять по TTL; добавить тест, что
`RETENTION-SENTINEL` не появляется в state.

**Regression.** `tests/test_client_api_secret_retention.py` — FAIL на текущем коде:
`RETENTION-SENTINEL unexpectedly found`; `evidence/new-regression-tests.log`.

### F3 — P3: restricted-режим оставляет plain WireGuard listener и UDP 51820

**Evidence.** `admin.py:368` при `init` всегда `restrictedNetwork:True`; `admin.py:179` в `render`
пропускает peer'ы при restricted; но `admin.py:152-159` `rules` без ветки restricted добавляет
`INPUT ... --dport 51820` (wireguard) и `51821` (awg); `init` запускает `wg-quick@xio0`. `public`
(`admin.py:333`) скрывает `wireguard`, создавая расхождение «скрыт в профиле, но слушает/открыт».
Тест `tests/test_protocol_controls.py::RestrictedPortTests` FAIL: в captured commands есть
`iptables ... --dport 51820 ...` и `ip6tables ... 51820`.

**Impact.** restricted-профиль не достигает заявленной минимизации поверхности: plain WireGuard
остаётся доступен для сканирования/фингерпринтинга, хотя клиентам не выдаётся; увеличивает риск
блокировок/деанонимизации. Не является обходом аутентификации.

**Exact minimal fix.** При `restrictedNetwork` не запускать `wg-quick@xio0` и не добавлять правила
51820 (оставить только AWG 51821); либо явно задокументировать, что restricted не скрывает WireGuard.
Добавить regression-тест, который проверяет отсутствие 51820 в `rules` и отсутствие
`wg-quick@xio0.service` в `init` для restricted.

### F4 — P3: FORWARD/MASQUERADE для OpenVPN не привязаны к входному интерфейсу

**Evidence.** `server/managed/network_stack.py:57-59`: для `10.80.0.0/24`, `10.81.0.0/24`,
`10.82.0.0/24` правила:
`FORWARD -s <subnet> -o <outbound> ... ACCEPT` и `POSTROUTING -s <subnet> -o <outbound> ... MASQUERADE`
без `-i xioovpn0/1`/`xiorivet`; для 10.82 TUN вообще `None`. `admin.rules` также добавляет NAT без `-i`,
хотя FORWARD для AWG/WG содержит `-i`.

**Impact.** На общем VPS локальный процесс/контейнер с CAP_NET_RAW и адресом из этих подсетей может
использовать сервер как NAT-релей; удалённый эксплуатант без локального доступа — нет. Defense-in-depth,
не подтверждено live.

**Exact minimal fix.** Для каждой подсети добавить `-i` соответствующего TUN (`xioovpn0`, `xioovpn1`,
`xiorivet`) в FORWARD и POSTROUTING; удалять/не добавлять 10.82, если интерфейса нет. Проверить
`test_network_stack`/`test_network_delta` и добавить assert на `-i`.

**Regression.** `tests/test_protocol_controls.py::ForwardingScopeTests` — FAIL: 6 правил без `-i`;
`evidence/protocol-control-tests.log`.

### F5 — P3 (residual trust): manifest не связывает bootstrap/update scripts

**Evidence.** `tools/package-server.py:18-21` пишет `xio-bootstrap.sh`/`xio-server-update.py` как
MIRRORS, а manifest (`:111`) содержит только `{schema, recipeVersion, sha256}` tar. Приложение
проверяет только tar (`managed_service.dart:297-303`) и исполняет bootstrap/update как root.
Штатный trust anchor — подпись/целостность пакета приложения, но отдельной привязки скриптов к
манифесту нет.

**Impact/NOTE.** Если пакет приложения/ассеты скомпрометированы, это уже RCE; отдельная защита нужна
для supply-chain/defense-in-depth и точечного аудита. Не P0.

**Exact minimal fix.** Добавить в manifest `artifacts: {bootstrap: sha256, update: sha256, ...}`;
приложение проверяет их перед `ssh.executeInput`; CI проверяет mirrors. Тест —
`tests/test_release_artifact_consistency.py` (mirror equality) уже фиксирует drift.

## 4a. Negative/abuse checks (matrix)

| Проверка | Результат | Доказательство |
|---|---|---|
| Admin API: чужая роль, quota, revoke не своего пользователя, duplicate id/key | PASS (отклоняется) | `test_admin.py`, `test_client_api.py`; 73-test suite |
| Client API: неверный token, action вне allowlist, неверный serverId, повтор запроса | PASS | `test_client_api.py` + `test_client_api_secret_retention.py` (retention — отдельный FAIL) |
| Xray: no-TLS/allowInsecure/unsafe file/sockopt/dialerProxy, malformed endpoint | PASS (Parse отклоняет) | `internal/xrayclient` Go tests |
| OpenVPN: отзыв cert/CRL, удаление client cert | PASS (mock) | `test_protocol_controls.py::OpenVPNRevocationTests`; live handshake не проверен |
| Cloak: revoked UID не попадает в BypassUID; replay cache/ timestamp — source inspected | PASS (scope); replay live не проверен | `test_protocol_controls.py::CloakScopeTests`; `vendor/cloak/internal/server/state.go` |
| AWG: неверный ключ/endpoint/timeout, unauthenticated candidate | PASS (Validate/Run отклоняют; typed completion) | `internal/awgactivation` tests |
| Host/endpoint/command injection: scheme/port/brackets/userinfo/newline/bad labels; uid 32 hex; args lists без shell | PASS | `test_host_validation.py`; source review `admin.py`/`network_stack.py` |
| Archive traversal/symlink/duplicate/absolute/hash | PASS | `test_update.py`; `tests/gnu-tar-extraction-check.sh` |
| Secret logs: client API error generic/log_message off; OpenVPN verb 0; Cloak verbosity error; admin error generic | PASS (source review); live journal не читался | source lines |

## 5. Проверенные контроли (PASS)

- **Обновление**: `server/managed/update.py:134-143` проверяет SHA256, absolute/`..`/symlink/
  duplicates/размер; существующие `test_update.py`/`test_update_ipv6.py` проходят; откат/идемпотентность
  проверены. `tools/package-server.py` проверяет pinned native SHA256 и детерминированный архив.
- **Admin/client API boundary**: `authority` (role/quota/owner-only admin), `serverId`, точный allowlist,
  `hmac.compare_digest` для token hash, idempotent op; `test_admin`, `test_client_api` PASS
  (8 OK, 2 POSIX-skip). Wrong token/revoked role/foreign revoke/duplicate create отклоняются.
- **Xray**: `xrayclient.Parse` запрещает no-TLS/allowInsecure/unsafe file/sockopt/dialerProxy и
  не-разрешённые top-level поля; `protectedDialer` принимает только numeric endpoint; Go tests PASS.
  Restricted `stack.config` не содержит revoked UUID/Shadowsocks (mock PASS).
- **OpenVPN**: tls-crypt-v2, CRL, client cert, `remote-cert-tls client`, `allow-compression no`;
  mock `revoke` генерирует CRL, удаляет cert (PASS). Live handshake/CRL reload не проверялись.
- **Cloak**: revoked UID не попадает в `BypassUID`; `ProxyBook` — только `127.0.0.1:1195`; mock PASS.
  Live wrong-UID/replay — не проверялись.
- **AWG**: `awgactivation.Validate` ограничивает ключ/endpoints/timeout, `Run` требует typed
  authenticated initiation от точного candidate, `AwgTurnOn` закрывает TUN FD на всех ошибках,
  `protectedAwgBind` защищает сокеты; Go tests PASS (`awgactivation`, `physical`, `mobile` не
  запускался из-за Android/TUN; targeted packages PASS).
- **Physical DNS/kill-switch**: `Resolve` не использует system DNS, `Dial` требует protect callback;
  Linux policy blackhole для отсутствующего family; Windows WFP fail-closed/dynamic; `internal/desktop`
  и `xiofirewall` Go tests PASS; **live WFP/TUN не проверялись**.
- **GNU tar**: hostile archive (absolute, `../`, symlink + path) → `tar_rc=2`; absolute stripped,
  symlink entry not followed, no file outside temp; `evidence/gnu-tar-extraction-test.log`. Это
  свойство GNU tar 1.35, не собственная проверка bootstrap; update.py имеет явную проверку.
- **Domain install**: `valid_host`/`valid_name` принимают домен/IP/trailing dot/Punycode и отвергают
  scheme/port/brackets/userinfo/space/newline/bad labels (`test_host_validation.py` PASS);
  OpenVPN/Cloak/profile tests для IP/domain PASS. Live DNS/SAN — за parent'ом.

## 6. Dependency/artifact trust

- Python server: stdlib; системные `openvpn`, `strongswan`, `wireguard-tools`, `iptables` ставятся
  apt/dnf **без версии** (residual supply-chain risk; `--no-install-recommends` уже есть).
- Go direct: `amnezia-tun2socks v2.5.6`, `amneziawg-go v3.1.20260814`, `Cloak v1.1.2`,
  `xray-core v1.260724.0` (local `vendor/xray` replace), `quic-go v0.64.0`, `utls v1.8.3-...`,
  `cbor v2.9.6`; `go.sum` присутствует. `vendor-metadata/rivet-build.json` pins server/AAR SHA.
- `mesh-pins.json`: headscale 0.29.5 SHA256 `e979...`, tailscale 1.104.1 SHA256 `108d...`; runtime
  download HTTPS with SHA check.
- `app/assets` manifest currently only tar hash; F1/F5.

## 7. Ограничения / что не проверено

Нет SSH/VPS, поэтому **не проверены** фактический bootstrap/install/init на Debian/Ubuntu/RHEL,
systemd/iptables/nft/capabilities/TUN, реальные handshake'и AWG/Xray/OpenVPN/Cloak/IKE/RIVET,
CRL reload, Cloak replay/wrong UID, WFP live, Windows/Android device, domain DNS/SAN live.
Не запускались benchmarks, fuzzing, govulncheck (parent), CI/публикации, adb/device.
Тесты на Windows используют только тестовые shims; POSIX-only transport/permission tests skipped.
Никакой сертификации/гарантии безопасности не заявляется.

## 8. Воспроизведение и артефакты

Корень артефактов:
`work/tg211-domain-security-20261031/deployment-security/`

- `tests/test_release_artifact_consistency.py` — release drift gate (сейчас 10 subtest FAIL).
- `tests/test_client_api_secret_retention.py` — private-key retention (сейчас FAIL).
- `tests/test_protocol_controls.py` — revoke/CRL, Cloak scope, Xray scope PASS; restricted port и
  forwarding scope FAIL.
- `tests/gnu-tar-extraction-check.sh`, `tests/compare_packaged_source.py`.
- `evidence/`: `server-tests-3.log` (73 OK, 2 skip), `client-api-tests.log` (8 OK, 2 skip),
  `go-targeted-1273-tests.log` (Go 1.27.3), `go-desktop-firewall-tests.log`, `gnu-tar-extraction-test.log`,
  `domain-host-tests.log`, `findings.json`, `packaged-binaries.txt` (SHA256 крупных бинарников;
  сами копии не хранятся),
  `new-regression-tests.log`, `release-artifact-tests.log`, `packaged-vs-source-summary.txt`,
  `sha256-audited-before/after.txt`, `git-status-before/after.txt`.
- `backup/`: копии 9 аудированных файлов; SHA256 before/after совпадают для server/managed и
  `tools/package-server.py`. `app/lib/managed_service.dart` менялся параллельно другим исполнителем
  (текущий SHA `b9e565d8...`), не нами.

Быстрые команды (Windows, только тестовые shims):

```powershell
$env:PYTHONPATH=(Resolve-Path 'work/tg211-domain-security-20261031/deployment-security/shims').Path
python -m unittest discover -s server/managed -p "test_*.py" -v
python -m unittest discover -s work/tg211-domain-security-20261031/deployment-security/tests -p "test_*.py" -v
Remove-Item Env:PYTHONPATH
```

Ожидаемо: server suite PASS; новые regression tests FAIL до исправлений F1/F2/F3 (и F3 port).

## 9. Статус

Source review + локальные negative/positive tests выполнены. Findings передаются parent'у; исправления
и live-установка — зона parent (у него VPS/SSH/credentials). Никаких production-правок этим агентом не
сделано; device/Android не затрагивался. До пересборки `app/assets` и прохождения изолированной
установки релиз нельзя считать проверенным.
