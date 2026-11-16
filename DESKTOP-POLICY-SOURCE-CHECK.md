# Desktop G4 source check and implementation status

Base `c946c920f764770c62312a68d4d104c0e2dea90a`; own branch `agent/policy-desktop-native-20261106`. No main merge, no push, no publication. Apple out of scope; this slice is the Go desktop helper.

Status update 2026-11-06: WIRE-V2 is the binding contract and the Go slice is implemented on this branch — see `DESKTOP-POLICY-GO-REPORT.md` for what is implemented/proven/blocked and for the pending `policyValidate` proposal. The earlier "API coding awaits parent decision" note is superseded.

## Wire decisions recorded for the helper

- Plan `schema` 2 with `profiles[]={id,protocol,endpoint,configDigest}`; `configDigest` is lowercase hex SHA-256 over the exact saved/base UTF-8 config bytes (no trim/reformat/reserialize; no DNS overlay/lease/revision). The four parent-verified goldens are asserted verbatim in tests.
- Plan `routing` must be JSON `null` on desktop; a non-null value is `POLICY_INVALID`, never ignored. `priorityProtocol` is an exact string or null. Manual plans are exactly `selectedId` and one entry; a malformed multi-id manual plan is rejected, never truncated.
- Versioned requests: begin/commit/reconcile exactly eight keys, abort exactly three (`version`, `instanceNonce`, `transactionId`), ACK exactly six keys. The transport enforces exact key sets.
- Activation attachment: `PolicyReceiptJSON` (six fields) on the existing capitalized connect request; candidate id/protocol must match the committed plan and the raw config digest is re-derived before any effect.
- Helper restart invalidates the instance nonce and starts blocked; readiness requires an explicit reconcile with clean resource evidence.

## Bounded existing resource evidence inventory (verified in source)

Linux: root-owned `/run/xio-client.lock` ownership journal (`XIO019-routing-owned\n`), `xio019` interface, dedicated table 28691 and rule priorities 18018/18019. The evidence adapter only reads: it never calls `prepareNetwork` or `cleanupLinuxOwned`. Successful enumeration with no reserved resource is the functional clean path; reserved markers are owned; failed/unsafe enumeration is unknown.

Windows: `ProgramData\XIO\tunnel.lock` (a live tunnel holds it with no sharing), `firewall.receipt` (exact legacy owned-rule name only), leftover `sharing.json`, and the `xio019` interface. Dynamic WFP needs no receipt. Presence of a held lock/valid receipt is owned; a malformed receipt is unknown, never clean.

Cooperating ownership has two independent parts: the per-store helper claim and the shared fixed-resource namespace claim (`xio019`), both process-lifetime. Singleton/claim success does not imply resource absence; read-only evidence is still required for stale or noncooperating leftovers. No immunity is claimed against noncooperating privileged or legacy tools.

## Validation constraints honoured

No privileged helper launch, elevation, OS network change, real product lock, service, account or credential was used. Verification is offline Go on the authorized Debian host in the owner's workspace with `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2` and `-p 1`; Windows is a cross-build/vet check only (App Control blocks unsigned Go execution). Tests use injected observers, owned temporary fixture locks and in-process dispatch; no sockets, VPN, TUN, routes or firewall.
