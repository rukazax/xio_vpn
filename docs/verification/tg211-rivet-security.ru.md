# TG211 — RIVET: негативные проверки защиты

Дата: 31.10.2026, МСК. Область: `protocol/rivet/internal/rivet` (RIVET-S1 / RIVET-H3).
Канонический worktree: `C:/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/repo-edit`,
HEAD `689ac18e9978bea20205763b85263181e0ef264e`; дерево уже было dirty до этой задачи.
Это локальная проверка кода и loopback-тесты, **не аудит всего VPN и не security certification**.

## 1. Границы и ограничения

Разрешено и выполнено только локально:

- чтение и правка `protocol/rivet/internal/rivet/**` и тестов в этом пакете;
- loopback-тесты (`net.Pipe`, `127.0.0.1`, временные каталоги), `go test`, `go vet`, короткий fuzz;
- evidence в `work/tg211-domain-security-20261031/rivet/**` и этот отчёт.

Не выполнялось: SSH/VPS, реальные DNS/публичные сертификаты, сеть, TUN, firewall, устройства,
подпись, CI, публикация. Родитель отдельно поднял минимальную версию `go.mod` до 1.27.3 и
добавил build-guards; эти изменения не откатывались. Финальные локальные тесты ниже
выполнены task-local `go1.27.3` с `GOTOOLCHAIN=local`; baseline — до этого bump, на
`go1.27.2`, и помечен как baseline, а не final. Пакета
`protocol/rivet/internal/cloak` не существует; `mobile/cloak.go` вне write-scope: код
прочитан, существующий loopback-тест `TestCloakCancellationAndProtection` запущен
read-only task-local go1.27.3 (PASS), новых Cloak-тестов не добавлялось.

`go test -race` недоступен на хосте: `CGO_ENABLED=0`, `gcc` отсутствует. Это зафиксировано как
ограничение, а не как «race-тесты пройдены».

## 2. Итог

| Проверка | Результат |
|---|---|
| baseline `go test ./internal/rivet` (go1.27.2, pre-bump) | PASS, 18.8 s; baseline, не final |
| baseline `go vet ./internal/rivet` (go1.27.2) | PASS |
| новые негативные тесты до правок | 5 ожидаемых FAIL (alias; lookup order ×2; revoked AuthOK; ошибка самого теста rate-limit) |
| новые негативные тесты после правок | PASS |
| final `go test ./internal/rivet` (task-local go1.27.3) | PASS, 78.6 s |
| final `go vet ./internal/rivet` (task-local go1.27.3) | PASS |
| fuzz `FuzzFrame` (go1.27.2 baseline / go1.27.3) | PASS 179 194 execs/5 s; PASS 2 677 execs/10 s |
| fuzz `FuzzFragments` (go1.27.2 / go1.27.3) | PASS 191 475 execs/5 s; PASS 6 803 execs/10 s |
| fuzz `FuzzCheckIP` (добавлен, go1.27.3) | PASS, 167 711 execs / 5 s |
| read-only `go test ./mobile -run TestCloakCancellationAndProtection` (go1.27.3) | PASS, 3.6 s |

Найдены и исправлены в рамках scope три дефекта/усиления. Критического обхода
аутентификации или расшифровки inner-канала в проверенной поверхности не найдено.
Отдельно, вне кода репозитория, остаётся toolchain-уязвимость `GO-2026-6809`
(раздел 4); она требует сборки на Go ≥ 1.27.3.

## 3. Находки и исправления

### RIVET-KEY-01 — key-reuse check обходился non-canonical base64 (исправлено)

`ClientConfig.Validate` сравнивал `c.Secret == c.EntryToken` как строки. Стандартный
`base64.StdEncoding.DecodeString` в Go принимает non-canonical варианты с ненулевыми
padding-битами: две разные строки декодируются в одни и те же 32 байта. Поэтому проверка
разделения ключей обходилась, если один и тот же ключ записать двумя разными base64-строками.

- Воспроизведение: `TestClientConfigRejectsBase64AliasedKeyReuse`; до правки тест падал
  с `reused key accepted under a different base64 spelling`.
- Исправление: `Validate` декодирует `Secret` и `EntryToken` и сравнивает байты через
  `subtle.ConstantTimeCompare`.
- Остаточный риск: `cmd/rivet user add` всё ещё сравнивает строки
  (`req.Secret == req.EntryToken`). Это вне write-scope; предложен патч в разделе 6.
  Практическая эксплуатация ограничена: клиент с таким профилем теперь отклоняется
  `Validate` до dial.

### RIVET-AUTH-01 — lookup до проверки carrier-параметров (исправлено)

`Session.ServerAuth` читал `Auth` (до 4096 байт), затем вызывал `lookup(id)` (в gateway —
чтение `users.json` до 1 MiB) и только после этого проверял `CheckParams`. Неаутентифицированный
peer мог слать произвольный ID с заведомо неверным carrier/trailing parameters и каждый раз
вызывать файловый lookup и HMAC, то есть усиливать ресурсную нагрузку до проверки параметров.
Это не обход аутентификации: HMAC всё равно проверялся.

- Воспроизведение: подтесты `carrier-downgrade` и `trailing-parameters` в
  `TestServerAuthRejectsForgedAndRevokedCredentials`; до правки `lookup calls = 1`,
  после — `0`.
- Исправление: `CheckParams(params, s.Carrier)` выполняется до `lookup`.
- Severity: низкая/средняя (DoS-hardening, зависит от размера `users.json` и числа
  одновременных слотов).

### RIVET-AUTH-02 — ServerAuth доверял lookup в вопросе revocation/ID/IP (усилено)

`ServerAuth` принимал результат `lookup` как уже проверенный: production
`Gateway.Lookup` действительно отклоняет `Revoked`, неверный `ID` и неверный IP, но сам
`ServerAuth` не проверял эти поля. При альтернативной реализации lookup или будущем
рефакторинге отозванный пользователь с валидным HMAC мог получить `AuthOK`.

- Воспроизведение: подтест `revoked-user` в
  `TestServerAuthRejectsForgedAndRevokedCredentials`; до правки сервер отправлял кадр
  `AuthOK` (frame 3), после — отклоняет до `AuthOK`.
- Исправление: `ServerAuth` проверяет `u.Revoked`, `u.ID == id` и валидность assigned IP
  (10.79.0.2–10.79.0.254) **до** отправки `AuthOK`/`Configure`.
- Это defense-in-depth; известного обхода production `Gateway.Lookup` не найдено.

### Что проверено и не дало обхода

- Unknown identity + proof, посчитанный с zero-secret fallback: отклоняется, потому что
  `lookupErr != nil` проверяется вместе с HMAC (`TestServerAuth.../unknown-identity-zero-secret`).
- Неверный secret, неверный carrier, trailing parameters: отклоняются.
- Кросс-привязка proof: смена TLS exporter или carrier меняет proof
  (`TestProofCannotCrossTLSOrCarrier`); inner TLS дополнительно требует TLS 1.3 +
  `X25519MLKEM768` + ALPN `rivet/1` + no-resume.
- TLS pin: неверный pin, классический/негибридный обмен, TLS 1.2 inner, resumption —
  отклоняются (`TestWrongPinRejected`, `TestNoClassicalGroupFallback`, `TestHybridAuthenticatedSession`).
- Просроченный сертификат при формально верном SPKI pin: отклоняется
  (`TestInnerTLSRejectsExpiredPinnedCertificate`).
- ServerName/SNI: identity сохраняется при numeric endpoint; неверный ServerName и
  пустой OuterCA для self-signed entry отклоняются в integration-тесте.
- `DecodeConfig` принимает только точный frozen-config; trailing/SID/IP overrides
  отклоняются (`TestDecodeConfigRejectsServerOverrides`).
- `Wire.ReadFrame`: truncated header/payload, oversized Challenge/IPPacket, zero Padding,
  unknown type, reserved byte, `n=0xffffffff` — ошибка/`ErrProtocol`, без паники;
  граничные 4096/1280 принимаются (`TestWireReadFrameTruncationAndBounds`).
- Reassembler: duplicate fragment идемпотентен, повтор уже собранного пакета игнорируется,
  конфликтующий duplicate/overlap отклоняется, частичные пакеты ограничены 64 и временем
  (`TestReassemblerRejectsTamperAndReplay`, `TestFragmentOverlapExpiryLimits`).
  Важно: одиночное искажение неперекрывающегося фрагмента на уровне reassembler не
  детектируется; целостность такого фрагмента обеспечивает TLS/QUIC транспорт, а не
  прикладной формат.
- До аутентификации `ReadPacket`/`SendPacket` возвращают `ErrProtocol`; `Close` снимает
  блокирующее чтение и отменяет контекст (`TestSessionRejectsDataBeforeAuthentication`,
  `TestSessionCloseUnblocksRead`).
- Entry token: отсутствующий/неверный/просроченный (удалённый из tokens.json) токен,
  не-Bearer, слишком длинный заголовок и rate-limit проверены
  (`TestEntryAllowedCredentialLifecycle`).
- Gateway `Lookup`: revoked, неизвестный ID, неверный IP, несовпадающий ID, повреждённый
  seal отклоняются (`TestGatewayLookupRejectsRevokedAndMalformedCredentials`).
- Outer trust selection: пустой `OuterCA` оставляет system roots, явный `OuterCA` заменяет
  их; inner pin использует `InsecureSkipVerify` + `VerifyConnection`, а не system roots
  (`TestOuterTrustSelectionAndInnerPin`).

## 4. GO-2026-6809 / CVE-2026-111943 — toolchain, не код RIVET

Источник: официальный `https://pkg.go.dev/vuln/GO-2026-6809` и
`https://vuln.go.dev/ID/GO-2026-6809.json`, проверено 31.10.2026. Родительский
`govulncheck` уже зафиксировал reachable-путь; здесь — анализ влияния на RIVET, без
повторного запуска сканера и без изменения toolchain. **Reachable ≠ proven bypass**: это
наличие вызова в графе, а не демонстрация обхода.

Суть advisory: `crypto/x509.Certificate.Verify` в Go до 1.27.3 (ветка 1.27) и до 1.26.10
(ветка 1.26) не применял denylist известных скомпрометированных intermediate-сертификатов.
Затронуты именно stale root-store сценарии с конкретными скомпрометированными
intermediate; это не «любой TLS сломан». Нужен сертификат, выданный через конкретный
затронутый intermediate, и позиция MITM/подмены DNS/маршрута.

### Reachability в нашем коде

- `DialWithTimeout` (S1 и H3) создаёт `outerTLS` через `outerTLSConfig`. При пустом
  `ClientConfig.OuterCA` `RootCAs == nil`, то есть Go использует системные корни.
  - S1: `tls.Dialer`/`http.Transport` handshake → `crypto/tls` → `crypto/x509.Verify`.
  - H3: `quic.Transport.Dial(..., outerTLS, ...)` → TLS 1.3 handshake → `crypto/x509.Verify`.
- При заданном `OuterCA` создаётся scoped pool; system roots не используются, но
  `Certificate.Verify` всё равно вызывается для построения/проверки цепочки. Для
  self-signed `GenerateOuter` в цепи нет публичных intermediate, поэтому данный сценарий
  практически не применим; для публичного сертификата с затронутым intermediate —
  применим.
- Inner RIVET TLS: `InnerTLS(pin)` ставит `InsecureSkipVerify = true` и собственный
  `VerifyConnection`, который проверяет ровно один сертификат, срок, SHA-256 SPKI,
  TLS 1.3, `X25519MLKEM768`, ALPN `rivet/1` и отсутствие resumption. Системные корни и
  цепочный `Certificate.Verify` здесь не используются. Поэтому GO-2026-6809 **не
  обходит inner pin и не позволяет выдать себя за gateway**.
- Gateway/Entry не требуют клиентских сертификатов и не вызывают `Verify` для клиента;
  серверная сторона этой ветки advisory не затронута.

### Последствия

Если entry использует публичный сертификат, выпущенный через затронутый intermediate,
клиент собран на уязвимом Go и outer trust store содержит этот intermediate, сетевой
атакующий с подходящим сертификатом теоретически может принять outer TLS на себя. Это даёт
ему entry token (bearer в `Authorization`), метаданные и возможность deny/relay. Он **не**
получает inner-ключи, не может расшифровать/изменить inner-трафик и не проходит HMAC
gateway без pin-ключа/секрета клиента. Автоматической эксплуатации и свидетельств активного
использования нет; утверждать «VPN скомпрометирован» нельзя.

### Меры

1. Собирать и поставлять бинарники на Go ≥ 1.27.3 (ветка 1.27) или ≥ 1.26.10 (ветка 1.26);
   родитель уже поднял минимальную версию `go.mod`/build-guards до 1.27.3 и перезапускает
   сборку/тесты/сканер. Финальные локальные тесты этого отчёта выполнены task-local
   go1.27.3 (`GOTOOLCHAIN=local`); baseline 18.8 s был на go1.27.2 и не является final.
2. Проверять build info релиза (`go version -m <binary>`), а не только версию на машине
   разработчика.
3. Предпочитать явный `OuterCA` (private CA или конкретный публичный корень) вместо
   system roots; это сужает trust и делает поведение воспроизводимым.
4. При подозрении на outer-MITM — ротировать entry token; inner pin и client secret
   считать не скомпрометированными, пока нет отдельных доказательств.
5. S1 outer допускает TLS 1.2 (`MinVersion` в `outerTLSConfig`); это не дефект данного
   advisory, но TLS 1.3-only был бы меньшей поверхностью, если deployment это позволяет.

## 5. Evidence

Корень: `work/tg211-domain-security-20261031/rivet/`.

| Файл | Содержание |
|---|---|
| `baseline-test.log` | baseline `go test`, PASS 18.8 s |
| `baseline-race.log` | race не запущен: `-race requires cgo` |
| `baseline-vet.log` | baseline `go vet`, PASS |
| `security-tests-before-fix.log` | 5 FAIL до правок (alias, lookup order ×2, revoked AuthOK, rate-limit); rate-limit FAIL был ошибкой самого теста и исправлен |
| `security-tests-after-fix.log` | новые тесты после правок (go1.27.2), PASS |
| `security-tests-after-fix-go1273.log` | новые тесты после правок на go1.27.3, PASS |
| `final-test.log` | полный `go test ./internal/rivet` после правок (go1.27.2), PASS 47.2 s |
| `final-go1273-test.log` | финальный `go test ./internal/rivet` на task-local go1.27.3, PASS 78.6 s |
| `final-vet.log` | `go vet`, PASS |
| `final-go1273-vet.log` | `go vet` на task-local go1.27.3, PASS |
| `fuzz-frame.log` | `FuzzFrame`, 179 194 execs, PASS (go1.27.2) |
| `fuzz-fragments.log` | `FuzzFragments`, 191 475 execs, PASS (go1.27.2) |
| `fuzz-checkip.log` | `FuzzCheckIP`, 212 476 execs, PASS (go1.27.2) |
| `fuzz-frame-go1273.log` | `FuzzFrame` на go1.27.3, PASS |
| `fuzz-fragments-go1273.log` | `FuzzFragments` на go1.27.3, PASS |
| `fuzz-checkip-go1273.log` | `FuzzCheckIP` на go1.27.3, 167 711 execs, PASS |
| `cloak-mobile-test.log` | существующий mobile Cloak loopback-тест, PASS 3.2 s (read-only, go1.27.2) |
| `cloak-mobile-test-go1273.log` | mobile Cloak loopback-тест на go1.27.3, PASS 3.6 s (read-only) |
| `scoped.diff` | diff только по `config.go`, `session.go`, новому тесту |
| `backup/pre/`, `backup/final/` | копии до/после для scoped-файлов |
| `SHA256SUMS.txt` | SHA-256 pre/final копий |
| `repo-head.txt`, `package-status.txt` | HEAD и статус пакета |

SHA-256 финальных файлов:

- `backup/final/config.go` — `606362ba4e7368024195455d933b14a8dbd09c82c04e9bd99eb1df7de680e2be`
- `backup/final/session.go` — `49eaf34294ab42e4f8b22cc0e836f7bbe9820729e7ff74e53c600209cef9d619`
- `backup/final/security_hardening_test.go` — `9e463854c19530f9a8207b04b9b97a3eccc88503a0a8adbc825558720d4439e4`

Актуальные хеши также перечислены в `SHA256SUMS.txt`.

## 6. Предлагаемый патч вне write-scope

`cmd/rivet/main.go`, ветка `user add`, сейчас:

```go
if req.Secret == req.EntryToken {
    fail(rivet.ErrProtocol)
}
```

Нужно заменить на сравнение декодированных значений, например:

```go
secret, e := rivet.Decode(req.Secret, 32)
if e != nil { fail(e) }
entryToken, e := rivet.Decode(req.EntryToken, 32)
if e != nil { fail(e) }
if subtle.ConstantTimeCompare(secret, entryToken) == 1 {
    fail(rivet.ErrProtocol)
}
```

(с импортом `crypto/subtle`; `secret` уже декодируется ниже, можно переиспользовать).
Патч не применялся: `cmd/rivet` вне разрешённого write-scope.

## 7. Воспроизведение

```powershell
cd C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\protocol\rivet
go test ./internal/rivet -count=1 -timeout=240s
go vet ./internal/rivet
go test ./internal/rivet -run=^$ -fuzz=FuzzFrame -fuzztime=5s
go test ./internal/rivet -run=^$ -fuzz=FuzzFragments -fuzztime=5s
go test ./internal/rivet -run=^$ -fuzz=FuzzCheckIP -fuzztime=5s
```

Ожидаемо: `CGO_ENABLED=0` и отсутствие `gcc` ⇒ `-race` не запускается; это не PASS.

## 8. Что осталось за границей

- Реальный VPS, публичный DNS/сертификат, сетевой MITM, OS trust store, TUN/firewall.
- Сборка и повторный `govulncheck` на Go 1.27.3 — выполняет родитель.
- Cloak: пакет `internal/cloak` отсутствует; `mobile/cloak.go` прочитан, существующий
  cancellation/protection loopback-тест запускался read-only; полноценный аудит Cloak и
  добавление новых тестов не выполнялись.
- Нагрузочное/многопользовательское DoS, rate-limit на масштабе, ротация ключей.
  `ServerAuth` после правки не делает lookup для неверных carrier-параметров, но всё ещё
  делает его для любого 16-байтового ID с валидными params; для полного устранения нужен
  rate-limit/кэш users, это не менялось в рамках задачи.
- Проверка destination-политики не покрывает все network-specific NAT64/6to4-префиксы
  (например, local-use NAT64); маршрутизация и firewall gateway остаются обязательным
  слоем. Это остаточный риск, а не доказанный обход.
- Proof не включает ID клиента: ID связывается через выбор секрета в lookup. Если оператор
  выдаст двум пользователям одинаковый secret, один сможет аутентифицироваться как
  другой; генератор `new-secret` создаёт уникальные значения, но CLI не проверяет
  дубликаты секретов между пользователями.
- S1 outer допускает TLS 1.2 (inner всегда TLS 1.3 + pin); TLS 1.3-only — рекомендация,
  требующая проверки совместимости deployment.
- Полная формальная верификация протокола и криптографический аудит: не выполнялись.
- Race-детектор на Windows-хосте недоступен (`CGO_ENABLED=0`, нет `gcc`); родитель
  отдельно запускает изолированный Linux `-race` по `./...`, это не входит в evidence
  данного отчёта.

Вывод: в проверенном локальном scope исправлены конкретные дефекты и добавлены
воспроизводимые негативные тесты; это не подтверждает безопасность всего VPN.
