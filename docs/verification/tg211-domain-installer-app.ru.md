# TG211: домен в установщике XIO и security-проверки app-пути

Дата: 31.10.2026, 01:53–04:00 MSK. Задача владельца TG211, XIO VPN only (не x1o).
Канонический dirty-репозиторий: `C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit`,
HEAD `689ac18e9978bea20205763b85263181e0ef264e`. Существующая работа не перезаписывалась:
сделаны backup, scoped diff и SHA256. Изменялись только `app/lib/**`, `app/test/**` и этот отчёт;
`app/assets`, `server/**`, `protocol/**`, `tools/**`, сеть, VPS, SSH, устройства и секреты не менялись.

## 1. Главная находка: canonical app/assets не является installer’ом текущего сервера

Это не только «старый номер recipe», а несовместимый legacy-архив:

| Проверка | Canonical `app/assets` | `server/managed` |
|---|---|---|
| `xio-server-release.json` | `recipeVersion: 24`, `sha256: b5b44f…2247` | — |
| SHA256 `xio-server.tar.gz` | `b5b44f72934036ffbad469fdd31fb0142726995259a91bbbdeadedb590752247` | — |
| `RECIPE` в `admin.py` | **отсутствует**; жёстко `recipeVersion=24` | `RECIPE=25` |
| Пути `admin.py` | `/etc/x1o-managed`, `/usr/local/lib/x1o-managed`, `x1o-managed-v1` | `/etc/xio-managed`, `/usr/local/lib/xio-managed`, `xio-managed-v1` |
| `xio-bootstrap.sh` | SHA256 `86dc8128…cc64`, 26.10 | SHA256 `4f115394…7121`, 29.10 |
| `rivet-setup.py` | отличается | 30.10 |
| `dualstack.py` | содержит `/etc/x1o-managed` | 29.10, xio |
| `network_stack.py`, `stack.py`, `admin.py` | отличаются | 29–30.10 |

Манифест **самосогласован**: его SHA256 действительно равен SHA256 архива. Поэтому app-проверка
«архив = манифест» проходит, но это не делает архив текущим installer’ом. `xio-bootstrap.sh`
распаковывает legacy `admin.py` в `/usr/local/lib/xio-managed`, а сам `admin.py` ожидает
`/usr/local/lib/x1o-managed` и `/etc/x1o-managed`. Это смешанный x1o/xio bundle, а не просто
устаревшая версия. Установка с canonical assets не может считаться рабочей; parent должен
пересобрать assets через `tools/package-server.py` (parent scope).

Проверка (`app/test/asset_provenance_test.dart`, opt-in) в текущем дереве даёт ровно этот список:

```text
archive admin.py RECIPE=absent but manifest recipeVersion=24
server/managed/admin.py RECIPE=25 but manifest recipeVersion=24
admin.py differs from server/managed/admin.py
rivet-setup.py differs from server/managed/rivet-setup.py
dualstack.py differs from server/managed/dualstack.py
network_stack.py differs from server/managed/network_stack.py
stack.py differs from server/managed/stack.py
app/assets/xio-bootstrap.sh differs from server/managed/bootstrap.sh
```

## 2. Что исправлено в app-пути

### 2.1. Установка больше не доверяет только запрошенному домену

`ManagedService.install` теперь:

1. требует проверенный `SHA256:` fingerprint SSH; без него установка не начинается;
2. валидирует `publicHost` общим `normalizeServerHost` **до** любых загрузок;
3. делает read-only `inspect` до загрузки. Если установка уже `ready`, она переиспользуется:
   bootstrap и старый архив не загружаются, server host берётся из ответа сервера;
4. если `inspect` показывает незавершённую установку — жёсткий stop, без загрузки;
5. если сервер подтвердил другой VPN-адрес:
   - при явно заданном другом `publicHost` — ошибка до загрузки (для ready) или после `init`
     (для fresh);
   - при пустом `publicHost` и SSH-прокси — принимается **server-confirmed** host, а не прокси;
6. сохраняет `ManagedServer.host` = SSH transport, `port` = SSH port, `publicHost` = подтверждённый
   VPN host. Прокси никогда не попадает в AWG/RIVET endpoint.

### 2.2. Манифест релиза проверяется по SHA256

Добавлен `ServerRelease` (`app/lib/managed_service.dart`):

- `schema == 1`;
- `recipeVersion` — целое ≥ 1;
- `sha256` — 64 lowercase hex;
- `verifyArchive(bytes)` сравнивает фактический SHA256 архива с манифестом.

Проверка применяется и в `install`, и в `ensureUpdated` перед передачей архива. Это закрывает
подмену/повреждение архива, но **не** закрывает stale recipe при самосогласованном старом
манифесте; для этого нужен build-time provenance gate (см. §5).

### 2.3. Host-key pin и пароль

- `SshPasswordGate`: пароль отдаётся только после `accept(fingerprint)`; до проверки ключа
  `release()` бросает `StateError`. Повторный `accept` другого ключа в одной сессии запрещён.
- `VpsService.open` создаёт gate на сессию, вызывает `accept` только после `SshHostKeyStore.verify`,
  а `onPasswordRequest` идёт через `gate.release(password)`.
- Добавлен `SshClientFactory` — тестовый seam; production по умолчанию использует `SSHClient`
  с теми же callbacks. Это позволило проверить порядок «pin → password» без реального SSH.
- `canonicalServerHost`: DNS-имена в known-hosts приводятся к lower-case и без одного trailing dot.
  `FR-HOST.FR`, `fr-host.fr.` и `fr-host.fr` — один pin; смена ключа через alias-написание
  отклоняется, второй записи не появляется.

### 2.4. Домены, IPv4, IPv6, Punycode

Установка и генерация профилей проверены для:

- `fr-host.fr`;
- `xn--bcher-kva.example` и `XN--BCHER-KVA.example`;
- `198.51.100.42`;
- `2001:db8::42` и `[2001:db8::42]` (в `init` уходит raw IPv6, в endpoint — скобки).

AWG endpoint: `serverEndpoint(publicHost, 51821)`; RIVET endpoint: `serverEndpoint(publicHost, 8443)`;
RIVET `serverName` остаётся независимым (`gateway.example`). SSH-прокси `ssh-proxy.example:9046`
не встречается ни в одном профиле.

Отклоняются до `inspect`/загрузки: scheme, `host:port`, `user@`, `;`, `/`, `?`, `#`, `_`,
leading/trailing hyphen, `..`, bracketed IPv4, `[IPv6]:port`, `fe80::1%eth0`, `xn--`,
Unicode-имя без Punycode, имя длиннее 253.

## 3. Тесты и результаты

### 3.1. Новый детерминированный набор

`app/test/install_domain_security_test.dart` — 20 тестов:

- manifest parse/SHA mismatch;
- точные upload bytes: bootstrap command и archive bytes равны asset bytes, timeout 30 мин;
- stale archive отклоняется до upload;
- матрица домен/Punycode/IPv4/IPv6 + реальные AWG/RIVET конфиги;
- malformed hosts не вызывают ни `inspect`, ни upload, ни `init`, ни запись store;
- ready installation переиспользуется без загрузки старого bundle;
- явный другой host для ready server отклоняется до upload;
- incomplete installation — hard stop;
- fresh `init` с другим host не регистрируется;
- вредоносное AWG-расширение от сервера (`Jc = 4\nPostUp = id`) отклоняется, пользователь
  отзывается через `revoke`; Xray/Cloak ответы проходят `ExtendedProfile.parse` до сохранения;
- `SshPasswordGate`;
- fake SSH client: pin проверяется до password; mismatch — 0 password requests;
- case/trailing-dot alias — один pin;
- Punycode DNS: A/AAAA спрашиваются для Punycode-имени, адрес не подменяется.

`app/test/install_domain_live_test.dart` — opt-in live installer, по умолчанию skipped.
`app/test/asset_provenance_test.dart` — opt-in packaging gate, по умолчанию skipped.

### 3.2. Команды

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\app
C:\dev\flutter\bin\flutter.bat analyze --no-pub
# No issues found! (ran in 9.9s)

C:\dev\flutter\bin\flutter.bat test test\install_domain_security_test.dart --no-pub
# All tests passed! (+20)

$env:PATH='C:\Program Files\Git\usr\bin;'+$env:PATH
C:\dev\flutter\bin\flutter.bat test --no-pub
# All tests passed! (+185 ~10)
```

`+185 ~10` — полный app-suite; 10 skipped включают opt-in live/lab/desktop тесты. Без
`C:\Program Files\Git\usr\bin` падают только `account_access_test`, `https_probe_test`,
`probe_tls_test` из-за отсутствия `openssl` в PATH — это ограничение окружения, не этих изменений.

Stage без platform/build каталогов:

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\work\tg211-domain-security-20261031\app\stage\app-final
C:\dev\flutter\bin\flutter.bat test test\install_domain_security_test.dart test\domain_host_test.dart test\server_address_test.dart test\asset_provenance_test.dart test\install_domain_live_test.dart --no-pub
# All tests passed! (+64 ~2)
```

Server host boundary (read-only, без изменений server):

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit
python server\managed\test_host_validation.py
# Ran 3 tests ... OK
```

Packaging audit (ожидаемо красный до пересборки assets):

```powershell
cd app
$env:XIO_ASSET_AUDIT='1'
C:\dev\flutter\bin\flutter.bat test test\asset_provenance_test.dart --no-pub
# Some tests failed: 8 проблем из §1
```

## 4. Точный API для реального install через домен

Parent открывает SSH сам (VPS/credentials — parent scope), затем вызывает ровно product-путь:

```dart
final ssh = VpsService(
  hostKeys: SshHostKeyStore(File(knownHostsPath)),
);
await ssh.open(
  SshTarget(sshHost, sshPort, 'root', sshPinOrEmpty),
  sshPasswordOrEmpty,
  privateKeyPemOrEmpty,
  passphraseOrEmpty,
);
final store = AppStore()..directory = workDirectory;
final service = ManagedService(ssh, assets: candidateAssets);
final server = await service.install(store, publicHost: vpnHost);
// install: inspect -> [готово: reuse без upload] / [fresh: manifest SHA -> bootstrap -> init]
final inspect = await service.command({'action': 'inspect'});
// inspect['phase'] == 'ready'; inspect['server']['host'] == server.publicHost
```

`ManagedService` уже принимает `AssetBundle? assets`; это и есть seam. Для candidate assets нужны
ровно три ключа:

- `assets/xio-server-release.json`;
- `assets/xio-server.tar.gz`;
- `assets/xio-bootstrap.sh`.

Live-тест использует `XIO_LIVE_ASSETS_DIR` — каталог с файлами `xio-server-release.json`,
`xio-server.tar.gz`, `xio-bootstrap.sh` (basename). Это позволяет проверить пересобранный bundle
без изменения canonical `app/assets`.

```powershell
cd app
$env:XIO_LIVE_INSTALL='1'
$env:XIO_LIVE_SSH_HOST='VPS-...ssh.provider.example'
$env:XIO_LIVE_SSH_PORT='9046'
$env:XIO_LIVE_SSH_USER='root'
$env:XIO_LIVE_SSH_PIN='SHA256:...'
$env:XIO_LIVE_SSH_PASSWORD='...'          # или XIO_LIVE_SSH_KEY_FILE
$env:XIO_LIVE_VPN_HOST='vpn.example'      # домен/Punycode/IPv4/IPv6
$env:XIO_LIVE_ASSETS_DIR='C:\...\candidate-assets'
$env:XIO_LIVE_CREATE_USER='1'
$env:XIO_LIVE_RESULT='C:\...\tg211-live-result.json'
C:\dev\flutter\bin\flutter.bat test test\install_domain_live_test.dart --no-pub
```

Секреты передаются только через process env, не сохраняются в тесте/репозитории. Live-тест не
делает uninstall и не меняет firewall/TUN/устройства.

## 5. Actionable missing gates (parent/packaging)

1. **Rebuild `app/assets`** через `tools/package-server.py`; текущий архив — legacy x1o, а не
   installer. Пока это не сделано, canonical install обречён.
2. **Build-time provenance gate**: запускать `XIO_ASSET_AUDIT=1 flutter test test/asset_provenance_test.dart`
   в packaging/CI. Gate должен требовать:
   - `manifest.recipeVersion == server/managed/admin.py RECIPE`;
   - `archive/admin.py` содержит `RECIPE=` и он равен manifest;
   - SHA256 `admin.py`, `rivet-setup.py`, `dualstack.py`, `network_stack.py`, `stack.py` равны
     server/managed;
   - SHA256 `xio-bootstrap.sh` равен `server/managed/bootstrap.sh`.
3. **Manifest fields**: добавить `bootstrapSha256` и `archiveRecipeVersion` (или `sourceRecipeVersion`)
   и проверять их в app; сейчас manifest не описывает bootstrap и внутренний recipe архива.
4. **Runtime minimum**: после пересборки можно ввести минимальную допустимую `recipeVersion`
   (25) в `ServerRelease`, чтобы app отказывался ставить заведомо старый bundle. Это решение
   parent/product; в этой задаче assets не менялись.
5. **Ready reinstall**: оставить проверку `inspect` перед upload (уже сделано) и покрыть gate
   в packaging smoke-тесте; иначе повторная установка может перезаписать более новый server
   старым архивом.

## 6. Границы

- Реальный VPS/SSH, DNS, сертификаты, RIVET handshake, AWG data-plane, firewall/TUN и устройства
  **не запускались**. Это parent scope; здесь только локальные loopback/детерминированные тесты.
- `SshPasswordGate` — app-level defense-in-depth. `dartssh2` сам проверяет host key до userauth;
  live lab test всё равно нужен для фактического сервера.
- `install` при fresh `init` может обнаружить mismatch хоста только после bootstrap+init; для
  ready-сервера mismatch ловится до upload. Гонка «ready появился между inspect и init» остаётся
  теоретической; серверный `init` в этом случае вернёт `existing`, app отклонит другой host.
- Это не security certification и не доказательство отсутствия утечек. Отчёт фиксирует локально
  проверенные инварианты и известный packaging-блокер.

## 7. Файлы, backup, hashes

Изменены:

- `app/lib/server_address.dart` — `5F2A971045A58CA8CED73FF4B588E6EDB7EE0761A12A581CE916A4D7BE6E2514`;
- `app/lib/core.dart` — `F19348FA73ECE8BAF5227FD7E1FC0DC5E7C4EA7DB56A12C31C2024B70D077643`;
- `app/lib/managed_service.dart` — `E70E50A82D8BCE5525875FC84D5B33B692098B4709937843B69B1D64F671D876`;
- `app/test/domain_host_test.dart` — `5204200A88EB429E394F30C4756206EE99842B1364C1694966AA4E53A5C7A7D8`;
- `app/test/server_address_test.dart` — `E20B2B04C52F330A1C7BE2020B9DC03A648BAF51FE939374F814AA88CA76BCF5`.

Добавлены:

- `app/test/install_domain_security_test.dart` — `97236C0398D32D0F2E65B2FAB2C6B49161E2B446DB1AAC30F9520E3F7EC734BE`;
- `app/test/install_domain_live_test.dart` — `CFA003A79C9AF2F7D6FB963165107E3BFE6BDB33B8BA4D79F7CF72DEFF25593A`;
- `app/test/asset_provenance_test.dart` — `828864D550DF022C78A58843AAE23AB9D3059FC46E7B0A3C3A4ECEF1D36710DB`.

Backup исходников до правок: `work/tg211-domain-security-20261031/app/backup/**`
(`core.dart` `1DE32F57…36CE`, `managed_service.dart` `A03977FC…9B61`,
`server_address.dart` `36C3B72C…DC14`, `domain_host_test.dart` `171EE24B…E129`,
`server_address_test.dart` `A9822A45…D36B23`).

Scoped diff: `work/tg211-domain-security-20261031/app/diff.patch`,
SHA256 `18AD04FBB52FDEDEFFB0FA8F976D1F443A0B5E08A4898F698025A7EC31FBB782`.
Stage: `work/tg211-domain-security-20261031/app/stage/app-final`.

Никаких commit/revert/build APK/release/CI/publication не выполнялось. Секреты и live VPS
не использовались.
