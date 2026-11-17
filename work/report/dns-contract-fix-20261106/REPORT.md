# C2 / P2: plain AWG DNS setting matches the native contract

## Scope and design

Exclusive branch `agent/dns-contract-fix-20261106`, clean base `641f6f80de6b267904f44f2c19593407a119a702`. Parent-approved design before product edits. This closes the DNS **setting/current issuance** contract and legacy setting repair, not retroactive validity of previously generated profiles. No acceptance/integration/release claim: parent independently reviews the commit.

[managed_models.dart](../../../app/lib/managed_models.dart) now accepts only unicast numeric IPv4/IPv6 resolver addresses compatible with desktop `netip.IsGlobalUnicast` and `!Is4In6`: private IPv4, documentation addresses and ULA remain valid. Unspecified, loopback, link-local, multicast, limited broadcast, mapped IPv4-in-IPv6, zones, hostnames, schemes, ports and paths are rejected. Leading-zero IPv4 is rejected consistently with Go. No DNS lookup or implicit DoH/DoT/bootstrap was introduced. The whole selected list is validated **before family filtering**, so a mixed invalid selection cannot silently discard the user's resolver and use another one.

Native readiness IPv4/IPv6 fail-closed filtering and the existing legacy IPv6-capability behavior are unchanged. In particular, a legacy IPv6-only resolver choice is not silently replaced by IPv4; native explicit readiness with no selected DNS family still fails. This setting remains for new AWG profiles, not a claim that RIVET/Xray/other protocols obey it.

The only [core.dart](../../../app/lib/core.dart) change is the DNS load handling around lines 823–830 (including all-blank selection compatibility). It preserves an unsupported nonempty stored string list exactly, instead of replacing it with Quad9 or marking all storage corrupt. Missing/empty persisted DNS retains the historical default. Unrelated saves retain the original unsupported setting; explicit `setDnsServers` validation allows repair. No connect/routing/lifecycle section changed. Existing imported/generated configurations, including possible AWG search-domain semantics, are **not rewritten or globally banned**.

[DNS settings page](../../../app/lib/app_settings.dart) keeps the legacy text editable and shows a correction error on entry. Two existing DNS strings were updated in each of 13 localization source dictionaries, without reformatting or regenerating binary assets. Error text is localized at rendering. No screenshot policy, startup setting, check-site, server or schema change.

[ManagedService.createUser](../../../app/lib/managed_service.dart) and [Subclients.create](../../../app/lib/subclients.dart) validate and snapshot DNS before UID/key generation, pending persistence, or remote add. Later profile generation uses the validated snapshot, not a mutable setting after an await. Invalid legacy settings leave existing delegated pending identity/private material unchanged. Remote family-readiness compensation remains the existing behavior; this is not an owner durability redesign.

## Independent source confirmation

Original setting validator accepted hostnames and UI advertised domains. Android's actual vendored [Interface.parseDnsServers](../../../vendor/amneziawg/android/src/main/java/org/amnezia/awg/config/Interface.java#L873) interprets nonnumeric hostnames as search domains, not selected numeric resolvers. Desktop [ParseProfile](../../../protocol/rivet/internal/desktop/profile.go#L131) requires numeric unicast nonmapped addresses. No actual Android packet leak is claimed or tested.

## Execution isolation and reproducibility

Linux via `ssh debian17-root` (192.168.88.17), preinstalled `/opt/flutter` 3.47.7 / Dart 3.13.5 and `/opt/go1.27.3`. Generated files, own copied pub/Go caches, HOME, XDG_DATA_HOME, TMPDIR and source are under `/srv/archives/agent-dns-contract-fix-20261106`. Cached dependencies only: `flutter pub get --offline`, `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`. No external DNS/HTTP, device, TUN, route/service, installation, unsigned Windows executable, SAC bypass or user-home secrets. Existing related tests use synthetic fakes and local loopback fixtures only.

Exact environment and named test commands are in [run-linux.sh](run-linux.sh) and [run-go.sh](run-go.sh). Source staging used `git archive HEAD` of app source/tests/pubspec/analysis options, protocol/rivet and needed tracked vendors. Baseline overlaid only the new regression fixture, not production edits. Unchanged test assets were copied from the earlier isolated source; `git diff 3da0535d96b3c139ddad2b80b7fc8b457f30a6a6 HEAD -- app/assets` was empty. Updated localization text was then overlaid. Normal Flutter test asset/shader compilation stays in the isolated build directory, not repository binary assets.

Commands (SSH stdout/stderr captured in logs):

```sh
bash /srv/archives/agent-dns-contract-fix-20261106/run-linux.sh baseline
bash /srv/archives/agent-dns-contract-fix-20261106/run-linux.sh fixed
bash /srv/archives/agent-dns-contract-fix-20261106/run-go.sh
```

Initial staging command failed with exit 1: archive selected absent `vendor/tailscale`, leading to an invalid empty tar and failed extract/scp; corrected selection excludes that unused missing directory. No product consequence. A localization edit command initially hit PowerShell smart-apostrophe parsing (exit 1, no edits), then JSON validation needed `ConvertFrom-Json -AsHashtable` due existing case-distinct keys; all 13 dictionaries subsequently parsed successfully. No language files were broadly serialized/reformatted.

## Tests and evidence

- [Baseline](baseline.log): 2026-11-05T21:32:22Z, **exit 1**, nine expected-red tests. Hostname accepted; unspecified address accepted; invalid legacy DNS admitted/normalized; owner/delegated fake remote boundaries reached before validation; legacy settings page lacked error. No real remote operation was issued.
- [First fixed run](fixed-first.log): focused analyzer **exit 0**; helper, actual storage and effect guards passed. Four test failures were investigated: new test needed to scroll to Save; existing assertion expected old error wording; two existing widget tests required InkSparkle shader omitted by `--no-test-assets`. Fixtures were corrected and normal test assets enabled; no production workaround.
- [First complete green run](fixed-final.log): focused analyzer **exit 0**, **126/126 tests passed**, exit 0. Includes existing app settings, managed models, account access/subclients, native profile readiness, domain host, install-domain security, server address, managed update verification and all localization tests.
- [Expanded matrix](fixed-expanded.log): **134/134 tests passed**, analyzer and tests exit 0. The subsequent all-blank legacy-default fixture initially needed formatting and triggered a `use_null_aware_elements` analyzer info (exit 1, [log](fixed-complete.log)); fixed to the SDK's null-aware map entry syntax.
- **Final exact source:** [validation.log](validation.log), 2026-11-05T21:48:01Z, **135/135 tests passed**, exit 0; focused analyzer all 7 files reports no issues, exit 0. Missing, empty and all-blank persisted selections retain the prior default, while nonempty invalid selections never substitute another resolver.

[New regression tests](../../../app/test/dns_contract_test.dart) cover literal/native-address matrix, mixed selections, actual persisted legacy load-save-repair for hostname/loopback/mapped addresses, absence of whole-store corruption, missing/empty default semantics, invalid owner/delegated zero remote/persistence effects (including existing pending record), valid pre-effect snapshot across setting mutation, and actual UI repair. Existing [app settings tests](../../../app/test/app_settings_test.dart) now require literal DNS and preservation rather than silent resolver substitution. Existing [native family tests](../../../app/test/native_profile_readiness_test.dart) are unchanged and run in full.

[First Go matrix](go.log) completed with exit 1: its inherited IPv4-only profile fixture correctly rejected the four IPv6 positives because [profile.go:257–259](../../../protocol/rivet/internal/desktop/profile.go#L257-L259) requires DNS addresses to have a configured payload family. The probe fixture was corrected to dual-stack Address/AllowedIPs; production Go source is unchanged. All IPv4 positives and special-address negatives passed in that first run. The long command startup was build/cache disk I/O, not DNS/network probing.

[Go probe](dns_contract_probe_test.go) is injected only into the isolated source test tree and calls the **actual unmodified ParseProfile**. It never performs resolution/activation: all endpoints are numeric fixtures. It includes public/private/ULA/mixed positives and hostname/special-address negatives matching the Dart matrix. **Final actual Go result:** [go-green.log](go-green.log), command started 2026-11-05T21:57:15Z, **24/24 subcases pass** (9 positive, 15 negative), parent test passes, exit **0**. No Go production edit or skipped-vet workaround was used.

## Source identity and formatting

Final [local SHA256](local-sha256.txt) and [Linux SHA256](linux-sha256.txt) match for all 20 modified app source/test/catalog files. [Go SHA256](go-sha256.txt) independently matches local and executed Linux parser/probe sources. All background jobs have been collected; none remains running. Base archive SHA256: `ef615ec6cee4348f52dc9aec28d851ea8ba467114a91650753f03ab1dccd99b1`; retained at `/srv/archives/agent-dns-contract-fix-20261106/source-base.tar`. The verified duplicate local staging tar was removed, not committed.

`dart format --output=none --set-exit-if-changed lib/managed_models.dart lib/app_settings.dart test/dns_contract_test.dart test/app_settings_test.dart` exits 0 (4 unchanged files). The three tiny core/service/subclient hunks were not whole-file reformatted, to preserve other workers' unrelated sections. `git diff --cached --check -- app` exits 0. Raw evidence logs retain tool output whitespace; no credentials or raw user profiles were collected. Git author/committer dates are explicitly UTC in the final commit, whose exact hash is provided in the parent handoff.

## Boundaries

No phone/native Android execution, physical resolver reachability, Windows signed-runtime/DPAPI execution, live profile activation, packet capture, complete application suite or all-protocol DNS-policy claim. Other workers' core routing sections and parent checkout were not edited. Existing invalid generated profiles require explicit user repair/re-import and are not silently rewritten.
