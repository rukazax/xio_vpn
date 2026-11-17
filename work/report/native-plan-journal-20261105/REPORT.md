# Native cascade plan / encrypted resumable intent — 2026-11-05

## Scope and result

Source-only foundation for the owner VPS wizard, **not a finished wizard or release**.

- [Plan and keys](../../../app/lib/native_cascade_plan.dart): exact server identities and SSH SHA256 pins; canonical literal exit; independent explicit inner-family intent; immutable selected egress interfaces; paired X25519 keys plus PSK; fixed native ingress map; hop-SNAT for two full nodes with overlapping native prefixes. Public plan/config serialization contains no private keys. Key restoration verifies both actual X25519 public keys, not only Base64 length.
- [Journal](../../../app/lib/native_cascade_journal.dart): production CredentialVault backend with injectable test I/O; await write and readback before returning prepared intent; preserve keys/operation identity and pending action on unknown outcomes; refuse blind next mutation, stale revision writers, corrupt records and configuration-identity substitution. Strict finite safe error codes. Cross-instance serialization is **within one app process**, not an inter-process lock.
- No automatic remote remove/direct rollback or journal deletion is provided. The future coordinator must bind authenticated inspections/proofs to both expected nodes/configurations before confirming steps. Journal progress itself is not proof of routing or successful profile migration.

## Exact verification

Linux snapshot: `/srv/archives/snapshots/native-plan-20261105`; Flutter **3.47.7**, Dart **3.13.5** ([SDK](sdk.log)). Snapshot base `a751864a38fe755018b716f6b42e6964fcac890b` plus exact new four Dart files and the independently supplied update-await source/tests from `e18980c87662c87602ff39c9c0096e626d641b0d`.

Executed [scoped runner](run-scoped.sh), all exit 0:

```sh
dart format lib/native_cascade_plan.dart test/native_cascade_plan_test.dart lib/native_cascade_journal.dart test/native_cascade_journal_test.dart
dart analyze --fatal-infos lib/native_cascade_plan.dart test/native_cascade_plan_test.dart lib/native_cascade_journal.dart test/native_cascade_journal_test.dart lib/managed_service.dart test/managed_update_verification_test.dart
flutter test --no-pub --concurrency=1 --reporter expanded test/native_cascade_plan_test.dart test/native_cascade_journal_test.dart test/cascade_identity_test.dart test/cascade_servers_test.dart test/managed_update_verification_test.dart test/install_domain_security_test.dart
```

**100 passed, no analyzer issues**: new plan 13 + new journal 8 + existing identity/server cases 56 + update/domain security 23. See [tests](tests.log), [analysis](analyze.log), [format](format.log), [six tested-source hashes](source-receipt.json). All six local files were compared byte-for-byte by SHA256 with tested snapshot files after retrieving formatter output.

[Python comparison](compare-python-config.py) ran using ordinary WSL Linux Python because importing the Linux connector on Windows fails at its required `fcntl` import. No fake `fcntl` or platform-policy bypass. Real `validate_config` result equals each generated public configuration; real `digest` equals Dart's asserted values:

- bridge: `0d96f1e7a5d9702c9998cc4d77a3156cfd84a0c9b067aea76c7aa9a60e805378`
- exit: `ed6a92120f7306d03a1b114605d9c28a1d9401f4e5a57c3d3a68927292be76c9`

[Recorded normalized cases](python-config-hashes.json) bind connector SHA256 `523fad66d3ba730884fa0a7e84a0937b74c3e031b9828fc87ca0c075522b1f4f` (map-pin milestone `3bad25e`). Cases contain public RFC7748 test vectors only, never production key material. Crypto/journal tests use fresh test-only keys and in-memory vault callbacks; they do not read device secrets.

Initial 68-case pass retained outside this committed report had one style info; braces corrected before the final fatal-info analysis. The final combined suite is the evidence above, not that initial run.

## Boundaries / next gates

Not implemented/accepted here: wizard/RPC adapter and terminal command delivery; remote install; durable native profile reissue/migration; multi-process journal serialization; actual encrypted platform vault runtime/power-loss behavior; native bindings or APK/packages; production reboot, provider egress, native client transport/device/anti-DPI acceptance; final full-tree release/provenance gates. Tests of archive verification ordering use fake SSH, not an update installation.

The Android vault flush/file-sync/parent-directory-sync source change is a separate compile-validation step, not covered by these Dart fake-I/O tests. Do not claim device or power-loss acceptance from this report. Apple targets remain deferred.
