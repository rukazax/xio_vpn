# DNS link-local follow-up: explicit native prefix masks

## Frozen baseline and independently found blocker

Parent: `daa31bee8867648a90f2875b98a8c5816a4ab693`, branch `agent/dns-contract-fix-20261106`. This is a **new follow-up commit, not an amend**. Original [report and evidence](../REPORT.md) remain unchanged as historical evidence, not an acceptance claim. The original 135 green tests did not adequately cover IPv6 link-local second-octet boundaries.

Independent reviewer e76 reported actual Dart SDK `isLinkLocal` using `0xb0` rather than the required `/10` mask `0xc0`: a mixed owner selection containing `fe90::1` reached issuance, while Go-compatible site-local `fec0::53` was wrongly rejected. Parent authorized this bounded follow-up after runtime confirmation. No SDK or global getter is patched.

Our [new baseline](baseline.log), against the unchanged frozen helper, independently reproduces both sides: **2/2 expected failures**, exit 1, command started `2026-11-05T22:16:30Z`. The rejection loop returns `fe90::53`; the acceptance loop wrongly throws for non-link-local addresses. This is not merely inferred from SDK source.

## Narrow change

Only [managed_models.dart](../../../../app/lib/managed_models.dart) production code changes: DNS validation computes link-local from the parsed raw bytes:

- IPv6: first byte `0xfe` and `(secondByte & 0xc0) == 0x80`, exactly `fe80::/10`.
- IPv4: first bytes `169, 254`, exactly `169.254.0.0/16`.

All other DNS validation, family/readiness behavior, preservation/repair, pre-effect snapshots, and UI behavior remain unchanged. Private IPv4, ULA, and native-accepted deprecated IPv6 site-local addresses remain valid **addresses under this parser contract**, not a claim of actual resolver reachability. No whole-SDK override, global network predicate change, server/native production edit, profile migration, schema, asset/localization or other core change.

## Tests

[DNS regression tests](../../../../app/test/dns_contract_test.dart):

- Every second-octet value in `fe00::/8`: all 64 values `0x80..0xbf` rejected; all 192 outside that range accepted, including `fec0::/10`.
- IPv4 adjacent-prefix positives `169.253.1.53`, `169.255.1.53`; `169.254.1.53` rejected.
- Each of the 64 IPv6 link-local second-octet values in mixed resolver selections: owner has zero remote effects; delegated path has zero remote/persistence effects both with and without an existing pending record.
- Positive owner/delegated issuance and pre-effect snapshot remain working for `fec0::53`, not only IPv4.

[Initial fixed run](validation.log): **330/330 passed**, exit 0; analyzer seven focused files no issues, exit 0; formatter two files unchanged, exit 0. Includes all prior 135 tests, with 195 additional boundary/effect/site-local cases. A subsequent comment placement cleanup makes the raw-byte predicate easier to read without changing its expression. [Final exact-source run](final-validation.log), command started `2026-11-05T22:19:58Z`: **330/330 passed**, exit 0; seven-file analyzer no issues and two-file formatter unchanged both exit 0.

Exact offline commands and isolated environment are in [run-linux.sh](run-linux.sh). Existing own source/cache/HOME/TMPDIR under `/srv/archives/agent-dns-contract-fix-20261106` only; Flutter 3.47.7 / Dart 3.13.5. No downloads or infrastructure changes. The independent reviewer's in-flight Go matrix was not duplicated. After parent confirmed completion/all jobs collected, we read the independent [P2 review](../../../../../REVIEW-DNS-CONTRACT-20261106.md): its unchanged Go parser passed 54 subcases (original 24 + reviewer 30), rejecting fe90/fea0/febf and accepting fec0. Parser SHA256 `e7cacf374dc22af9719a20733e09606622a69d9da92e19e3eb31f970c7e83b02`. Only then was the separately prepared [dense probe](dns_linklocal_probe_test.go) started in our own existing cache/source via [run-go.sh](run-go.sh), covering the same 256 second-octet values and 3 IPv4 neighbors against actual unmodified `ParseProfile`, with valid dual-stack synthetic payloads. No lookup/activation and no vet suppression.

**Dense actual Go result:** [go.log](go.log), command started `2026-11-05T22:22:41Z`, **259/259 subcases passed**, parent test passed, exit **0** (0.029s). This confirms every tested second-octet classification against the actual native parser, not a replacement `netip`-only sample.

## Frozen source identity

[SHA256 manifest](source-sha256.txt) matches local and executed Linux files:

- Helper: `82d479765bbd2bb670e66ae6f11f06f5f7f13c1aedfabca1067a4b19b7214431`.
- Regression test: `df408f3640504a9cec7dc1842bb12f629df06da50650a08da5a81019913a6e71`.
- Actual unmodified Go parser: `e7cacf374dc22af9719a20733e09606622a69d9da92e19e3eb31f970c7e83b02`, identical to independent review.
- Dense Go test fixture: `dc71b0e812cdf50b94509797f42317125bf375e5f34cc60f1bf8a7bf5549be4e`.

Production delta is **5 added /1 removed lines in one helper**; only its focused Dart test and this new report subtree also change. All original reports and other source files remain untouched. `git diff --check -- app` exits 0. Raw evidence whitespace is retained. All four follow-up background jobs collected: expected-red baseline exit 1; initial fixed Flutter exit 0; final exact-source Flutter exit 0; dense actual Go exit 0. No task job remains running. New commit uses UTC author/committer dates; exact commit hash is supplied in parent handoff.

## Scope and remaining acceptance

This is a correction to the frozen DNS candidate, not a broader networking audit or a claim to have tested live resolvers. No phone, external DNS lookup, route/TUN/service activation, Windows unsigned executable, SAC bypass, or real user credentials/profile was used. Parent must independently review the new frozen hash before integration; this report does not self-accept the change.
