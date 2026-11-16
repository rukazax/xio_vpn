# G5 C0 — Go capsule-sealer primitive (implementation report)

**Status:** implemented and bidirectional Go↔Dart verified (real Dart 3.13.5 / pinenacl 0.6.0). **Scope:** C0 primitive only — no server prepared receipt, no CA/user provisioning, no installer wiring, no Store/A/Android changes, no live helper/network/VPS/device.

## 1. Base and ownership

| Fact | Value |
|---|---|
| Parent isolated composition | `2efbb18c7f4bb616fd20850483255da017389225` (G5 Slice A merge; primary `5a` untouched) |
| Owned worktree | `work/agent-g5-c0-sealer-20261106` |
| Owned branch | `agent/g5-c0-sealer-20261106` |
| Accepted A code | `app/lib/issuance_canonical.dart` SHA-256 `760b6198ed68924ed68858d4d72cdea2461f5b2a173c45bfa05b15fbb5f22d71`, `app/lib/issuance_capsule.dart` SHA-256 `56bf90a2065149ac795a7b561eaf06d5f9c2398f2cc5ce16e1bf1774cdfda398` (unchanged) |
| Design source | `REVIEW-DURABLE-ISSUANCE-DESIGN-20261106.md` §9.1.2–§9.1.5; `G5-IMPLEMENTATION-SLICES-20261106.md` §3.2; frozen interop pin `REVIEW-CAPSULE-INTEROP-PIN058-20261106.md` (`x/crypto v0.58.0`) |

No product Dart file, pubspec, Store, A journal, Android or Go desktop runtime was modified. The only new product files are the Go package and command below.

## 2. Implemented surface

### `protocol/rivet/internal/issuancecapsule` (codec)

- `Seal(context, artifacts, recipientPublicKey) (Envelope, error)` — validates context/artifacts/recipient, encodes the accepted payload, seals with `golang.org/x/crypto/nacl/box.SealAnonymous` and `crypto/rand`, generates a random 16-byte lowercase-hex `capsuleId`, enforces the envelope size bound.
- `Open(envelope, recipientPrivateKey, expectedRecipientPublicKey, expected) (Context, artifacts, error)` — mirrors the accepted Dart guard order exactly: 32-byte key binding with derived public key (constant-time compares), **`len(ciphertext) <= 48` rejected before the box** (the pinenacl empty-plaintext trap), `box.OpenAnonymous` failure → `bad_box`, empty → `bad_box`, invalid UTF-8 / blank / non-object / missing / unexpected / schema / purpose / version / context / artifact-kind / artifact-size rejections, then closed artifact validation. It never returns plaintext without an expected context and never claims authenticity.
- `ParseEnvelope` — exact five-field closed envelope, strict types, canonical base64 spelling, decoded lengths (`recipientPublicKey` 32, `ciphertext` ≤ 32816), envelope JSON ≤ 45056, duplicate-key and depth guards.
- `Envelope.JSON()` — exact accepted field order (`v`, `alg`, `capsuleId`, `recipientPublicKey`, `ciphertext`), canonical base64, no extra fields.
- `CanonicalJSON` — v1 canonical encoder used for context equality: sorted keys, no whitespace, integers/bools/strings/lists/maps, ASCII-only strings, null/float rejection.

Constants (exact accepted values): `v=1`, `alg=nacl-box-sealed-x25519-xsalsa20-poly1305-b2b24`, `purpose=owner-issuance/delivery`, plaintext ≤ 32768, ciphertext ≤ 32816, envelope ≤ 45056, artifact ≤ 8192, ≤ 8 artifacts, closed kinds `openvpn.client-key`, `openvpn.tls-crypt-v2-client`, `openvpn.client-cert`, `ikev2.password`, `tailscale.authKey`, `cloak.uid`.

Payload encoding mirrors the accepted Dart `_encodePayload` byte-for-byte: sorted top-level keys (`actor`, `artifacts`, `deployment`, `operation`, `profileSetDigest`, `purpose`, `requestDigest`, `schema`, `server`, `uid`, `version`), sorted artifact keys, Dart JSON string escaping (`\n` for LF, no HTML escaping, so `<`, `>`, `&`, `/` stay literal), and LF is allowed only in artifact values (PEM).

No cryptography is hand-rolled: the only crypto is `curve25519.X25519` for the public-key binding and `nacl/box.SealAnonymous/OpenAnonymous`; randomness comes from `crypto/rand`.

### `protocol/rivet/cmd/xio-issuance-seal` (stdin/stdout sealer CLI)

- Exactly one bounded JSON object on stdin (`≤ 262144` bytes): `{"context":{10 exact fields},"artifacts":{kind:string},"recipientPublicKey":"<canonical base64 32B>"}`; exactly one envelope JSON object (single line) on stdout.
- Any argv is rejected (`E_USAGE`) so a secret can never be passed in argv; no environment variable is read for secrets; no temp files; stdout contains only the envelope; stderr contains only finite codes (`E_USAGE`, `E_INPUT_TOO_LARGE`, `E_INPUT_SHAPE`, `E_CONTEXT`, `E_ARTIFACTS`, `E_RECIPIENT`, `E_SEAL`) with no error text or payload echo.
- Exit codes: `0` success, `2` bounded rejection, `1` internal write failure.

## 3. Go verification

Host: Debian `root`, `/opt/go1.27.3/bin/go` (go1.27.3), owned `HOME/TMPDIR/GOCACHE/GOPATH` under `/srv/archives/agent-g5-c0-sealer-20261106`, `GOMODCACHE` from the existing offline cache, `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2`, `-p 1`.

| Check | Result |
|---|---|
| `go build ./internal/issuancecapsule ./cmd/xio-issuance-seal` | 0 |
| `go vet` (linux + `GOOS=windows`) | 0 |
| `go test` (unit + CLI) | 0 |
| `go test -race` | 0 |
| `GOOS=windows GOARCH=amd64 go build/vet` | 0 |

Tests cover: exact payload golden; seal→open round trip; wrong recipient (both directions); context swap; tamper at `epk[0]`, tag offsets and last byte; truncation `0/1/32/47/48` → `short` and `49/50/n-1` → `bad_box`; 49-byte garbage; strict envelope shape/v/alg/capsuleId/base64/trailing; unknown artifact kind; empty/oversize/control-character artifact values; empty artifact map; multiline PEM with `<>&/` and LF preserved; plaintext > 32 KiB rejected; complete context validation matrix; CLI argv/empty/unknown-field/missing-field/bad-recipient/oversize inputs; secret never echoed on stdout/stderr.

## 4. Cross-runtime interoperability fixture (external, not product)

`review-fixtures/g5-c0-interop/` contains the accepted Dart files copied unchanged (`lib/issuance_canonical.dart`, `lib/issuance_capsule.dart`; hashes above), a `pubspec.yaml` pinned to `pinenacl 0.6.0`, and `bin/interop.dart`:

1. Go (`-tags interopfixture`, `INTEROP_DIR`) generates a synthetic envelope, the exact payload bytes, context, artifacts and the synthetic private scalar (TEST-ONLY).
2. The Dart appendix opens the Go envelope with the accepted Dart codec (`CapsuleEnvelope.parseStrict` + `CapsuleCodec.open`), verifies artifacts/context, re-seals the same context/artifacts with `CapsuleCodec.seal`, and writes the Dart envelope plus its raw plaintext.
3. Go verifies the Dart envelope opens with the same context, that artifacts match, and that the raw Dart plaintext is **byte-identical** to the Go payload encoder.

Deterministic data only; the private scalar and artifacts are synthetic test vectors; no real keys, no network. Dart runs on the same Debian host with an **owned** `PUB_CACHE` (`/srv/archives/agent-g5-c0-sealer-20261106/pubcache`, a copy of only `pinenacl-0.6.0`, itself with no runtime dependencies), owned `HOME`/`TMPDIR`/`XDG_CACHE_HOME`; the old review caches/configs are read-only and unmodified. To avoid even an offline `pub get` write, the fixture uses a manually created owned `.dart_tool/package_config.json` with an absolute `file://` root pointing at the owned `pinenacl-0.6.0` copy (generated on the host, gitignored). The single authorized Dart command is therefore only:

```sh
cd /srv/archives/agent-g5-c0-sealer-20261106/src/review-fixtures/g5-c0-interop
PUB_CACHE=/srv/archives/agent-g5-c0-sealer-20261106/pubcache \
HOME=/srv/archives/agent-g5-c0-sealer-20261106/home \
TMPDIR=/srv/archives/agent-g5-c0-sealer-20261106/tmp \
XDG_CACHE_HOME=/srv/archives/agent-g5-c0-sealer-20261106/gocache \
/opt/flutter/bin/cache/dart-sdk/bin/dart run bin/interop.dart /srv/archives/agent-g5-c0-sealer-20261106/interop
```

The owned `.dart_tool/package_config.json` points at absolute read-only roots of the owned copies (`pinenacl`, plus the accepted canonical code's `crypto` → `typed_data` → `collection` chain); no `pub get`, fetch, or write to any shared/old cache was performed (the accepted canonical file imports `package:crypto`, so that closure is required). Fallback (not used): copy only the needed packages into the owned cache and run `dart pub get --offline` with all paths owned.

Result: **PASS** (Dart exit 0, Go verifier exit 0). The accepted Dart codec opened the Go envelope, bound context/artifacts and re-sealed; Go then opened the Dart envelope (`dart-envelope.json` SHA-256 `14f84c12a2caac79e91c3833a467aa86be25a7fa59d0a271e997c04a94fb98bb`, capsule digest `e04275b5254c0782a65235738f72790b1d66d14053949b9c4bb19eb20d91373c`) and proved the raw payload bytes are byte-identical: Dart plaintext SHA-256 `cce2da3ce695bc8fe8a5981b465e3c1af85b05a6a4078adbae5bb4a89e2d9f29` equals the Go payload SHA-256, including sorted keys, LF-in-PEM and literal `<>&/`. `dart-result.json` SHA-256 `0195178f14af378b84e9d7ae168ca4040b0910baa2a774e0908914632b66341d` reports `opened=true` with the same artifacts.

The first attempt within the authorized slot failed because the accepted `issuance_canonical.dart` imports `package:crypto`, absent from the minimal config; only the owned config/cache was extended (exact versions `crypto-3.0.7` → `typed_data-1.4.0` → `collection-1.19.1`, copied read-only from the host cache) and the job reran successfully. No `pub get`, no writes to `/root/.pub-cache`, no old review root/config/cache change, and no Dart job remains running (slot released). Logs: `logs/dart-interop.log`, `logs/go-interop.log`.

## 5. Honest limits

- Anonymous encryption only: anyone holding the recipient public key can seal an accepted capsule. This codec gives confidentiality and context binding, never sender/CA authenticity, key validity, server behaviour, receipt authenticity or material correctness. Delivery trust stays with the pinned transport and the authenticated receipt.
- Artifact material is unvalidated here; callers must validate keys/certs/commitments before use, and the transport must be trusted.
- The CLI deliberately has no deterministic-ephemeral mode and no key generation; C0 is sealing only.
- No server prepared-receipt, CA, per-UID provisioning, installer copy, package metadata, Store/A/Dart pubspec/Go desktop runtime change, and no real network/service/device/VPS use.
- Module-wide `go build ./...` at this composition fails on unrelated `../../vendor/*` replacements that are outside the `protocol/rivet` subtree in this worktree; the affected packages build/vet/test cleanly and the failure is not caused by this change.

## 6. Source hashes and commands

| File | SHA-256 |
|---|---|
| `internal/issuancecapsule/capsule.go` | `b9f41c19927f8d2f3e96375457bf881404759fbbc6f2862e715bf11926fe5aa9` |
| `internal/issuancecapsule/capsule_test.go` | `4c70d534c34d47ef1b26d51bdfe1e9e62d1caaafe5c05a8ca4f3f70c2ea2382b` |
| `internal/issuancecapsule/interop_fixture_test.go` | `1112f9f34b29dceb368b197bbd5a228e39c2c136b0ec6ea92cbd97726e3af404` |
| `cmd/xio-issuance-seal/main.go` | `5762227412a0c6cf89de4cab3212c9ff2286e646e8809d19d505ee88e5645a91` |
| `cmd/xio-issuance-seal/main_test.go` | `17cc08590858f7af0f9d2307c26d53d30b986a989781cc4d7f1c277bd0b481d2` |

Logs: `/srv/archives/agent-g5-c0-sealer-20261106/logs/` (full-module build attempt and exits). Commit: _to be finalized after the Dart interop slot._
