# G5 C0 — revision R2: strict-parser forward repair (child of 800d)

**Status:** bounded forward repair committed as a child of the frozen `800d4bd` candidate. The old report `G5-C0-GO-CAPSULE-SEALER-REPORT.md`, the old `800d` proof and the reviewer logs are **not** modified or overwritten. Awaiting b9's final walker probe before this is a final candidate; no acceptance is claimed.

**Base:** `800d4bddeb4488d8cc20fc5962e04b298c1a1cad` (product `45f0d85`). This revision changes only the Go parser/CLI/public-Open checks, their tests, and the fixture `pubspec.yaml`. The sealed-box wire format, envelope fields, crypto algorithm, caps, artifact kinds and product Dart/pubspec/Store/A/runtime are unchanged.

## 1. Independent findings that this revision fixes

From `work/review-g5-c0-go-sealer-20261106` (immutable, untouched):

1. CLI accepted a second JSON value, trailing garbage, duplicate top/context/artifact keys, and quoted `schema`/`version` (7 of 14 raw-stdin cases exited 0 with ciphertext stdout). `logs/independent-adversarial.log`, `cli-vectors/summary.json` (SHA-256 `2354cba99d6b548db9d2547bda21bb51b6078eeaad8a08a7e46b772210df0e77`), `review_cli.py` (SHA-256 `242d1aa61ba846d12afd3f2ad81aa98b34af3e6c2ad20af70bdd273b5ad2839a`).
2. The runtime duplicate-key walker used a global `expectKey` toggle: after a nested object closed, the parent's next key was treated as a value and later values as keys. Result: a valid unique-key payload with equal repeated values (`requestDigest == profileSetDigest`, or `deployment == operation`) was rejected by `Open` as `not_json` after a successful `Seal`. Confirmed by b9's `logs/valid-repeated-values.log` and `source-800d4bd.tar` (SHA-256 `e73f3d81833d5966d3ceafe16f1e761507e77154790dd4f0e9406ac921244b99`).
3. The public `Open(Envelope)` accepted `v=2`, a bad `alg` and a bad `capsuleId` even though `ParseEnvelope` rejected the same wire values — a public-struct bypass of the envelope invariant.
4. The fixture `pubspec.yaml` declared only `pinenacl`, while the accepted `issuance_canonical.dart` imports `package:crypto`; the successful Dart run depended on a manually created, uncommitted package config. The ordinary declared offline bootstrap was therefore not reproducible.

## 2. Fixes (exact files)

### `protocol/rivet/internal/issuancecapsule/capsule.go`

- `checkNoDuplicateKeys` now parses **exactly one JSON value** with a bounded recursive `walkJSONValue` (depth ≤ 64), rejecting duplicate keys at every object level and trailing bytes/second values. Parent state is explicit: after a child object/array closes, control returns to the parent object loop, which still expects its next key. No global key/value toggle remains.
- `validateEnvelopeFields` is the shared invariant for `ParseEnvelope` and `Open`: `v == 1`, exact `alg`, 32 lowercase-hex `capsuleId`, 32-byte recipient key, ciphertext ≤ 32816 and envelope JSON ≤ 45056. `Open` runs it **before** key binding/crypto, so a direct struct cannot bypass the wire checks; rejection reasons stay finite (`envelope_shape` / `capsule_too_large`).

### `protocol/rivet/internal/issuancecapsule/request.go` (new)

- `ParseSealRequest` is the reusable strict stdin parser: one JSON value + EOF, duplicate scan at every level, exact top-level `{context, artifacts, recipientPublicKey}` and exact ten-field context, canonical base64 recipient, closed artifact kinds/values.
- Numeric fields use the byte-level `intValue` check, so `schema`/`version` must be **actual JSON integers**; quoted (`"1"`), decimal (`1.0`) and exponent (`1e0`) forms are rejected as `ErrSealRequestContext`.
- Typed sentinels (`ErrSealRequestShape/Context/Artifacts/Recipient`) let the CLI keep finite stderr codes without echoing errors.

### `protocol/rivet/cmd/xio-issuance-seal/main.go`

- Uses `ParseSealRequest`; no own `json.Decoder.Decode` single-shot path remains. Same bounded stdin cap, zero argv, no env/temp use, finite stderr codes only, secret-safety unchanged; `E_INPUT_SHAPE` for trailing/duplicate/shape, `E_CONTEXT` for non-integer or invalid context, etc.

### `review-fixtures/g5-c0-interop/pubspec.yaml`

- Declares `pinenacl: 0.6.0` and `crypto: 3.0.7` (the exact version from the accepted `app/pubspec.lock`), so a normal `dart pub get --offline` with the owned cache resolves the same dependency closure without a manual package config. No product pubspec is touched.

## 3. Same immutable probes, rerun

- Reviewer probe `review_adversarial_test.go` (SHA-256 `8ec7f973abfecbfd7fdcd0ae6f99e2c0f4589e575e0dc1758d540d578862b3d6`), copied verbatim into the package and run with `-run '^TestReview'`: **all pass**, including `duplicate after nested artifacts`, both equal-value round trips, public `Open` v/alg/capsuleId controls, bounds/kinds.
- Reviewer `review_cli.py` against the newly built binary: **14/14 cases `contractPass`**, exit 0. The regenerated vectors live in the owned `/srv/archives/agent-g5-c0-sealer-20261106/review-cli/cli-vectors/` (summary SHA-256 recorded in the run log); the reviewer's original tree was not written.
- Own Go tests (26 passing cases across the codec and CLI), `-race`, linux vet, `GOOS=windows` build+vet: all exit 0. `gofmt -l` on the changed packages is empty.

## 4. New source hashes (old → R2)

| file | 800d | R2 |
|---|---|---|
| `internal/issuancecapsule/capsule.go` | `b9f41c19927f8d2f3e96375457bf881404759fbbc6f2862e715bf11926fe5aa9` | `3b40aeca2397af8af1529e219fbce566c562600d6a337974a487aab784681b8b` |
| `internal/issuancecapsule/capsule_test.go` | `4c70d534c34d47ef1b26d51bdfe1e9e62d1caaafe5c05a8ca4f3f70c2ea2382b` | `3b6e38f6cfb5ef2e23d4c8fdac75c1ae46a2bf8457a66462e414434a0df9c35f` |
| `internal/issuancecapsule/request.go` | — | `0dc8eb87046cacc5bdf63b7fff7c28aa952222caa2b74bf1415904df620d65b8` |
| `cmd/xio-issuance-seal/main.go` | `5762227412a0c6cf89de4cab3212c9ff2286e646e8809d19d505ee88e5645a91` | `4256bcac933e1ebee3784dbba58c1b1dad04f4639f41dbf3537c65ae705e40d9` |
| `cmd/xio-issuance-seal/main_test.go` | `17cc08590858f7af0f9d2307c26d53d30b986a989781cc4d7f1c277bd0b481d2` | `204dcd140ad90bbcf94b8b226e672614ad4f6578e0fca08a7421b27fbb11cb97` |
| `review-fixtures/g5-c0-interop/pubspec.yaml` | (pinenacl only) | `d2bb5c981c1f9acd069b7448d9fd759d7133b137bde2402be2bf81ea805bc502` |

Unchanged: `interop_fixture_test.go` (`4c8d0a7846cdce18307ee5b52ee8cc045e18dc006b9c442d8af351f70669ce31`), the accepted Dart copies (`760b6198…`, `56bf90a2…`), and the C0 envelope/crypto/limits.

## 5. Evidence and commands

```
# Go (owned env, /opt/go1.27.3, GOPROXY=off, GOMAXPROCS=2, -p1)
go build ./internal/issuancecapsule ./cmd/xio-issuance-seal        # 0
go test -p 1 -count=1 ./internal/issuancecapsule ./cmd/xio-issuance-seal   # 0, 26 cases
go test -p 1 -count=1 -race …                                      # 0
go vet …; GOOS=windows GOARCH=amd64 go build/vet …                 # 0
go test -p 1 -count=1 -run '^TestReview' ./internal/issuancecapsule  # reviewer probe: PASS
python3 review_cli.py <owned-root>                                  # 14/14 contractPass
```

Logs: `/srv/archives/agent-g5-c0-sealer-20261106/logs/c0-r2/{build,test,race,vet,win-build,win-vet,test-verbose}.log` and `exits.txt`; reviewer-CLI run in `logs/reviewer-cli.log` + `review-cli/cli-vectors/summary.json`.

## 6. Residual and explicitly not claimed

- Dart interop was **not** rerun (b9 requested no Dart until a coordinated slot). This revision changes only parsing/validation, not the payload bytes, envelope or crypto; the existing 800d Dart proof remains the interop evidence and is preserved untouched. The equal-value round trip and nested-duplicate rejection are now covered by Go tests, which is sufficient to disprove the reported functional parser failure.
- The fixture `pubspec.yaml` change makes `dart pub get --offline` reproducible but was not executed in this revision (no Dart slot); the manual owned package config previously used remains valid.
- Pointer to b9: the walker fix is generic (recursive value/object parse), not a whitelist of the reported strings; any further duplicate/EOF case is expected to be covered by the same parser, but the final walker probe is still awaited.
- No product Dart/pubspec/Store/A/Android/Go-desktop change; no CA/receipt/provisioning; no new dependency; crypto algorithm unchanged.
