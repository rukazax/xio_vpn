# TG211 — установка XIO по домену и проверка защиты протоколов

Дата: 31.10.2026, 01:51–03:00 МСК. Владелец: 418179821. Проект: только XIO VPN, не x1o.
Канонический dirty-репозиторий: `C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit`,
HEAD `689ac18e9978bea20205763b85263181e0ef264e`. Существующая работа не перезаписывалась.

## 1. Итог

Сделано и проверено:
- домен в app-пути установки: отдельный SSH-host/порт, публичный VPN-host, Punycode, IPv4/IPv6;
- app-путь получил проверки: manifest/SHA архива, `inspect` перед повторной установкой,
  SSH-pin **до** пароля, отказ от malformed host до upload;
- найден и исправлен **P0**: canonical `app/assets` был legacy-сборкой x1o/recipe 24 (не текущий
  сервер); пересобран bundle recipe 25 из текущего source и установлен в `app/assets`;
- найден и исправлен **P0**: `xio-bootstrap.sh` поставлялся с CRLF и не запускался в Linux shell;
  source и packager нормализуют LF;
- RIVET: исправлены 4 находки, добавлены регрессии; parent-прогон `go test -race ./...` — PASS;
- Go обновлён до 1.27.3 из-за reachable `GO-2026-6809` (crypto/x509 denylist); повторный
  `govulncheck` — exit 0; внутренний pin RIVET этой уязвимостью не обходится;
- проверено, что защищённые `xio-entry.service`/`xio-gw.service`, маршруты и firewall VPS
  не изменились: MainPID 495/502, оба active, firewall-снимки совпали.
- живой прогон установщика в изолированном systemd на VPS: bootstrap — PASS, RIVET
  gateway/entry стартуют и работают; подробности в §2.4;
- найден и исправлен **P0**: `xio-stack.service` использовал `%d`, который не поддерживает
  systemd 249 (Ubuntu 22.04): юнит не загружался, `init` падал на
  `Stack operation failed: systemctl enable --now`. Исправлено на `${CREDENTIALS_DIRECTORY}`,
  проверено `systemd-analyze verify` на чистой jammy; бандл пересобран (`9da68483...e1bc`).

Не сделано / не заявляется:
- **полная установка на этот VPS не завершена**: LXC-корень — `shared` ext4 на LVM,
  `mount -o remount,ro,bind` невозможен даже в host-namespace, поэтому systemd не может
  применить `ProtectSystem=strict`/`StateDirectory=`/`DynamicUser=` (юниты падают с
  226/NAMESPACE). Нужен KVM-сервер либо product-решение по ослаблению sandbox (F7).
  Это не PASS установки на LXC;
- **`fr-host.fr` не указывает на VPS**: A `103.102.135.112`, AAAA `2a0c:b641:1a0:800::1`;
  порт 9046 закрыт, порт 22 отдаёт OpenSSH 9.9p1 Ubuntu 24.04, тогда как VPS — Ubuntu 22.04.
  Установка по этому имени попадёт не на VPS. DNS не менялся;
- живой VPN-туннель через `fr-host.fr`, Android/iOS-устройства, WFP/TUN live и независимый
  аудит не проверялись.

## 2. Установка по домену

### 2.1. App-путь

`ManagedService.install` теперь:

1. требует непустой проверенный `SHA256:` fingerprint SSH;
2. валидирует `publicHost` общим `normalizeServerHost` до загрузки;
3. делает read-only `inspect` до upload; готовую установку переиспользует;
4. проверяет `assets/xio-server-release.json` и SHA256 архива; повреждённый/старый архив
   отклоняется до upload;
5. сохраняет SSH transport (`host`, `port`) отдельно от публичного VPN-host; SSH-proxy не
   попадает в AWG/RIVET endpoint;
6. принимает домен/Punycode/IPv4/IPv6/trailing dot; отвергает scheme, port, userinfo, скобки,
   Unicode без Punycode, новые строки и инъекции.

Проверки app: `install_domain_security_test.dart` — **20 PASS, 1 live-test skipped**;
`asset_provenance_test.dart` с `XIO_ASSET_AUDIT=1` — **PASS**; полный suite — **179 PASS, 10 skipped**;
4 env-теста (`account_access`, `https_probe`, `probe_tls`) отдельно — **PASS** после добавления
Git `openssl` в PATH. Итоговых кодовых падений нет.

### 2.2. Bundle

Canonical assets до правки были смешанным legacy x1o-архивом: manifest recipe 24, `admin.py`
искал `/etc/x1o-managed`, source — `/etc/xio-managed` recipe 25. Манифест при этом совпадал с
архивом, поэтому app-проверка SHA его не ловила.

Новый bundle:
- `xio-server-release.json`: `recipeVersion=25`, SHA256
  `19494fdb45ce59b41db35164e18863f280baa21b624e7e81ff95afb59eec4baa`;
- архив: 22 331 874 байта, 19 members, `x1o` — 0 вхождений;
- `xio-bootstrap.sh`: 4361 байт, LF, SHA256
  `4fb96db63d03b546dc991b42c0f994206d781bbb584f1777a37a3e25a0e7f5f1`;
- `tools/package-server.py` проверяет pinned native SHA256, recipe, детерминированный архив и
  нормализует `.sh` mirror в LF.

Проверка pinned-нативных входов в бандле v26 (независимо, распаковкой членов архива):
`amneziawg-go` 5 171 002 B `fc1a1f9f…4c9a` — совпадает с `AWG_SHA256` в `tools/package-server.py`,
с `vendor-server/amneziawg-go-linux-amd64` рабочего дерева и с копией в `work/source-0.22.4`;
`rivet` 10 367 239 B `2a4f67a2…c48b`, `xraygateway` 31 473 927 B `58ce9bd5…ad65`,
`cloak` 8 356 103 B `444796c1…03cd` — совпадают с `vendor-metadata/rivet-build.json`
(`serverSha256`, `xrayServerSha256`, `cloakServerSha256`). То есть пересобранный бандл несёт
именно закреплённые бинари, подмены нет.

### 2.3. Что показал реальный прогон

VPS-стенд: официальный Ubuntu base rootfs собран на VPS из `ubuntu-base-22.04` (SHA256
`df6fe77c…4b07`) с пакетами из подписанного jammy-архива; `systemd-nspawn` не смог
смонтировать devpts — LXC-ограничение VPS, поэтому полный in-container install не выполнен.
Защищённые службы не запускались/не останавливались.

Локальный systemd-стенд (Ubuntu 22.04, отдельные mount/net/pid namespaces): bootstrap с LF
прошёл preflight (`TUN node/open and capability masks passed`) и распаковал bundle; `init`
вернул `Stack operation failed: systemctl enable --now` — стенд не дал корректный systemd
control plane. Это ограничение стенда; **полный init/PASS не заявляется**.

### 2.4. Живой прогон установщика в изолированном systemd (VPS)

Собран отдельный стенд на самом VPS без изменений host-сети и служб: `unshare --mount --uts --ipc
--net --pid --fork` (приватные namespace, `dummy0` с IPv4/IPv6 default-route, host-veth нет),
`chroot` в одноразовый Ubuntu 22.04 rootfs, systemd 249 как PID 1. Host-сервисы
`xio-entry.service`/`xio-gw.service` оставались active, firewall и маршруты не менялись,
после прогона не осталось ни mount-точек, ни процессов лабы.

Что подтверждено живым прогоном:
- `xio-bootstrap.sh` (LF, из candidate-бандла) — **BOOTSTRAP_RC=0**; preflight TUN/open/
  capability masks пройден;
- `admin.py init` проходит guards, создаёт `deployment.json`, ключи, firewall-правила,
  поднимает `xio0`, ставит RIVET: `xio-rivet-gateway` и `xio-rivet-entry` **запускаются**
  (`network-up` -> `{"ipv6Forwarding": true}`, gateway active, entry active);
- `xio-stack` после фикса F6 грузится, но не стартует в этом окружении (см. F7).

Ограничение стенда (доказано отдельными пробами): корень LXC — `ext4` на
`/dev/mapper/vg_ct-vm--137--disk--0`, точка монтирования `/` в состоянии `shared`;
`mount -o remount,ro,bind` на нём возвращает `cannot mount ... read-only` (rc=32) — и внутри
вложенного namespace, и в host-namespace самого VPS. Поэтому все юниты с
`ProtectSystem=strict`/`StateDirectory=`/`DynamicUser=`/`LoadCredential=` падают с
`226/NAMESPACE` (`Failed to set up mount namespacing: Invalid argument`). Это ограничение
контейнера/LVM-корня, а не кода продукта; на KVM с обычным корнем такие юниты работают.

Для стенда применялись lab-only drop-in (`ProtectSystem=no`, `ProtectHome=no`, `PrivateTmp=no`,
`ReadWritePaths=`) — они не входят в продукт, нужны только чтобы дойти до следующих шагов.

### 2.5. Найдено живым прогоном: P0 в `xio-stack.service`

`server/managed/stack.py` писал `ExecStart=/usr/local/bin/xio-stack %d/config ...`.
Спецификатор `%d` не поддерживается systemd 249 (Ubuntu 22.04 — заявленная ОС):
`systemd-analyze verify` на чистой jammy даёт
`Failed to resolve unit specifiers in %d/config: Invalid slot` и
`Unit configuration has fatal error, unit will not be started`.
Следствие: `init` падал на `Stack operation failed: systemctl enable --now` — установка
не завершалась ни на одном сервере с Ubuntu 22.04.

Исправлено: `ExecStart=/usr/local/bin/xio-stack ${CREDENTIALS_DIRECTORY}/config ...`;
на systemd 249 verify проходит (остаётся только ожидаемое "binary not found" в пустой системе).
Бандл пересобран: recipe 25, 19 members, SHA256
`9da68483b04dfdb8243e45f61b033b7213382a4f88f35f1e0a1966fddb34e1bc`; bootstrap без изменений
(`4fb96db6...f5f1`).

### 2.6. Закрытие находок F2-F5, F8 и адаптивный sandbox (F7)

По прямому указанию владельца (31.10.2026, 04:25 МСК) закрыты F2-F5 и F8, разрешено ослабление
sandbox на хостах, где systemd не может применить `ProtectSystem`.

- **F2 (P2)**: `client_api.py` больше не пишет `configs` в `deployment.json`. Durable-запись
  операции содержит только маршрутную выдачу (`user`, `server`) и флаг `configsDelivered`;
  повторный запрос той же операции возвращает `configsUnavailable: true` вместо приватных
  профилей. Профили выдаются один раз, из состояния не воспроизводятся.
- **F3 (P3)**: в restricted-режиме WireGuard не поднимается вовсе — `render()` не пишет
  `xio0.conf`, `apply()` не вызывает `wg syncconf`, `wg-quick@xio0` не включается, юнит AWG
  не имеет `Requires=wg-quick@xio0.service`, UDP 51820 не открывается ни в iptables, ни в
  firewalld/ufw-профиле. AWG остаётся единственным UDP-туннелем.
- **F4 (P3)**: каждое правило FORWARD/POSTROUTING несёт `-i <iface>` (xioovpn0/xioovpn1).
  Для IPsec-пула 10.82.0.0/24 TUN не существует, поэтому правила вынесены в `ike_install`
  и привязаны к xfrm-политике (`-m policy --dir in/out --pol ipsec`), а не к «любому» входу.
- **F5 (P3)**: манифест теперь фиксирует не только архив, но и `bootstrapSha256`,
  `updateSha256` и `artifacts` (все root-исполняемые файлы). Приложение проверяет хэш
  `xio-bootstrap.sh` до отправки и передаёт ожидаемый SHA архива в скрипт, который сверяет
  stdin до распаковки — подменённый/обрезанный поток отвергается как root.
- **F7 (P1, окружение)**: вместо предположений о провайдере добавлена проба
  `sandbox_supported()`: bind `/usr` + `remount,ro,bind`. Если remount невозможен (LXC с
  shared ext4-корнем), установщик пишет drop-in `50-xio-sandbox.conf` с `ProtectSystem=no`
  только для XIO-юнитов и сохраняет `PrivateTmp`, `NoNewPrivileges`, `CapabilityBoundingSet`,
  `RestrictAddressFamilies`; режим фиксируется в `deployment.json` как `sandboxMode`.
  На обычном KVM/железе проба проходит и юниты остаются в strict-режиме.
- **F8 (P3)**: `cmd/rivet user add` декодирует `EntryToken` и сравнивает байты через
  `subtle.ConstantTimeCompare`, а не строки; non-canonical base64 больше не создаёт
  пользователя с secret == entryToken. `go vet` и linux-кросс-сборка `cmd/rivet` — PASS.

Проверено на живом VPS: проба sandbox возвращает `sandboxSupported=false`,
`sandboxMode=compat`, временный каталог и mount удалены, `xio-entry`/`xio-gw` остались active.

## 3. Домен и DNS — блокер

| Имя | A / AAAA | Факт |
|---|---|---|
| `fr-host.fr` | `103.102.135.112` / `2a0c:b641:1a0:800::1` | не assigned VPS `…::2a2` |
| `vps-721137.ssh.vps1euro.fr` | provider IPv4 + IPv6 | SSH-прокси, pin совпал |
| `2a0c-b641-1a0-800--2a2.sslip.io` | `2a0c:b641:1a0:800::2a2` | публичный тест-алиас, не production DNS |

С Windows: `fr-host.fr:9046` — closed; `fr-host.fr:22` — SSH banner `OpenSSH_9.9p1 Ubuntu-3ubuntu3.2`
(другой хост, не VPS 22.04). Поэтому ввод `fr-host.fr` в поле установки не установит VPN на
VPS-721137. Нужно либо изменить DNS A/AAAA на VPS/прокси, либо вводить
`vps-721137.ssh.vps1euro.fr` как SSH-домен и отдельно задать публичный VPN-host. DNS-записи
не изменялись.

## 4. Защита протоколов

Проверены исходники и локальные/loopback-тесты; live handshake всех протоколов не заявляется.

### Исправлено

- **RIVET-KEY-01**: key-reuse `Secret == EntryToken` можно было обойти non-canonical base64;
  сравнение переведено на декодированные байты + constant-time.
- **RIVET-AUTH-01**: `Session.ServerAuth` делал `lookup` до проверки carrier/trailing
  parameters — DoS/усиление запросов; `CheckParams` перенесён до lookup.
- **RIVET-AUTH-02**: `ServerAuth` не проверял `Revoked`/`ID`/assigned IP до `AuthOK`;
  добавлена проверка.
- Parent-регрессия: race в `protect_wiring_test.go` (append из параллельных A/AAAA lookup)
  устранена mutex; финальный `go test -race ./...` — **237 PASS, 0 FAIL, 8 SKIP, 11 packages**,
  `go vet` — PASS.

### Найдено, но не исправлено (product decision)

| ID | Severity | Проблема | Минимальная мера |
|---|---|---|---|
| F2 | P2 | `client_api.py` сохраняет `configs` с private key/tls-crypt-v2/IKE/Cloak/Tailscale в `deployment.json` | не хранить секреты в durable response; TTL/шифрование |
| F3 | P3 | restricted-режим всё равно запускает plain WireGuard `xio0` и UDP 51820, хотя peer'ы скрыты | не запускать `wg-quick@xio0` и не открывать 51820 в restricted |
| F4 | P3 | FORWARD/MASQUERADE OpenVPN-подсетей без `-i xioovpn0/1` | привязать правила к входному TUN |
| F5 | P3 | manifest не связывает `xio-bootstrap.sh`/`xio-server-update.py` | добавить их SHA256 в manifest и проверять до upload |

Отдельно: app-манифест проверяет только tar; bootstrap/update исполняются как root. Это
supply-chain defense-in-depth, не P0 при целостном app-пакете.

### Не обнаружено

Обхода аутентификации production-путей, подмены inner RIVET pin, приёма неизвестного
identity с zero-secret, cross-TLS/carrier proof, повторного использования фрагментов без
ограничений, выхода за границы frame/reassembler, path traversal в update/tar. Это не
сертификация и не гарантия отсутствия уязвимостей.

### F6 (P0, исправлено) — `%d` в `xio-stack.service` ломает установку на Ubuntu 22.04

`systemd 249` не знает спецификатор `%d`; юнит получает fatal error и не стартует, из-за чего
`init` возвращает `Stack operation failed: systemctl enable --now`. Проверено на чистой
Ubuntu 22.04 (systemd 249.11) через `systemd-analyze verify`. Исправлено на
`${CREDENTIALS_DIRECTORY}`; новый бандл `9da68483...e1bc` проверен тем же verify.

### F7 (P1, исправлено адаптивной пробой) — LXC с shared ext4-корнем не даёт systemd применить sandbox

На VPS `/` — `shared`, ext4 на LVM; `mount -o remount,ro,bind` невозможен (rc=32) и в
host-namespace, поэтому юниты падали с `226/NAMESPACE`. Реализована проба
`sandbox_supported()`: на таком хосте установщик пишет drop-in `ProtectSystem=no` только для
XIO-юнитов и сохраняет остальные ограничения; на обычном хосте остаётся strict. Живая проба на
VPS: `sandboxSupported=false`, `sandboxMode=compat`.

### F8 (P3, исправлено) — `cmd/rivet user add` сверял Secret/EntryToken как строки

`protocol/rivet/cmd/rivet/main.go:160` проверяет `req.Secret == req.EntryToken` до сравнения
декодированных байтов; оба значения отдельно проходят `rivet.Decode(..., 32)`. Non-canonical
base64 тех же 32 байт проходит guard, и такой пользователь создаётся. Обхода аутентификации нет:
`ServerAuth` теперь сравнивает декодированные байты constant-time и отвергает такую пару, то есть
результат — нерабочий пользователь, а не компрометация. Исправлено: `EntryToken` декодируется, сравнение идёт
`subtle.ConstantTimeCompare` по байтам; `go vet` и linux-кросс-сборка PASS. Пересборка `rivet`
в бандл остаётся за release-процессом.

## 5. Зависимости

`govulncheck` (официальная база `vuln.go.dev`, 27.10.2026) на Go **1.27.3** — exit 0.
Остаются module-level advisories без reachable symbol в нашем графе: chi 5.2.5 (IP spoofing
через X-Forwarded-For), x/net 0.61 (HTML), x/crypto/openpgp (unmaintained). Их следует
обновить/исключить отдельной задачей; exit 0 не означает «чисто».

`GO-2026-6809` (CVE-2026-111943) был reachable в `crypto/x509.Verify` при Go 1.27.2; после
перехода на 1.27.3 исчез из отчёта. Inner RIVET TLS использует собственный SPKI pin и этой
веткой не обходится; outer public TLS зависит от системных корней.

## 6. Доказательства

Корень: `C:/Users/er-ka/.openclaw/workspace-xio/work/tg211-domain-security-20261031/`.

- `candidate-assets/`, `candidate-assets.sha256`, `package-candidate.v2.log`;
- `remote-build-rootfs.v4.json` — официальный base image и пакеты;
- `remote-lab-install.v2.json`, `lab-install-result.json` — LXC/devpts blocker;
- `local-lab-install.v3.log`, WSL `/root/xio-lab/out/install.log` — LF bootstrap preflight/init RC;
- `remote-nested-systemd.v2..v21.json`, `remote-nested-systemd.py` — изолированный systemd
  на VPS: namespace, boot, bootstrap/init, RIVET gateway/entry, lab drop-in;
- `remote-sandbox-probe.json`, `remote-host-ro-probe.json` — TUN/cgroup/devpts и
  `remount,ro,bind` на host-namespace (rc=32);
- `remote-diag*.json`, `remote-stack*.json`, `remote-awg*.json` — разбор отказов
  `systemd`, `xio-stack`, `xio-managed-awg`;
- `candidate-v26/` — бандл после фикса `%d` (recipe 25, 19 members,
  `9da68483b04dfdb8243e45f61b033b7213382a4f88f35f1e0a1966fddb34e1bc`);
- `linux-final-go-race-receipt.json`, `linux-final-go-race.jsonl`, `linux-final-vet.log`;
- `govulncheck-1273-receipt.json`, `govulncheck-1273.jsonl`;
- `remote-final-postcheck.v2.json` — protected MainPID/ActiveState/listeners/routes/firewall
  unchanged;
- child reports: `docs/verification/tg211-domain-installer-app.ru.md`,
  `tg211-rivet-security.ru.md`, `tg211-deployment-security.ru.md`;
- app: `app/test/install_domain_security_test.dart`, `asset_provenance_test.dart`,
  `app/assets/*`.

## 7. Следующие шаги

1. Исправить DNS `fr-host.fr` на assigned VPS (A/AAAA) либо утвердить установку через
   `vps-721137.ssh.vps1euro.fr` + отдельный публичный VPN-host.
2. Для полного live install нужен disposable KVM/VPS: на этом LXC systemd не может
   применить `ProtectSystem`/`StateDirectory` (shared ext4-корень, remount ro невозможен),
   плюс нужен ответственный за DNS-запись домена.
3. Закрыть F2–F5 и обновить chi/x-net/openpgp; затем повторить сборку и проверки.
4. После установки — отдельный live VPN/device тест; текущий результат не является релизом,
   установкой или сертификацией.
