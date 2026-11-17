# Desktop startup integration acceptance

Accepted source commit: `1e24a0594cc5dedc1b18fb31154d58c7d5bb6e4b`, automatic merge of `ba3566b6b2cd63ecedee8de11a5e549b5eb89958` and independently accepted `36fa869aff5b98152e06ba774f31d87491f03c57`.

## Independent execution

- [Complete top-level Flutter host suite](<full.log>): 768 passed, 18 skipped, zero failures; exit 0.
- [Client-focused set](<client.log>): 337 passed; exit 0.
- [Independent adversarial probes](<probes.log>): 12 passed; exit 0. Includes current-consent rechecks and obsolete startup versus newer manual UP ownership.
- [Analyzer](<analyze.log>): zero errors, zero warnings, two pre-existing INFO findings; exit 1, not a clean analyzer exit.
- [Source/asset/config verification](<post.log>): all frozen hashes matched; exit 0.
- [Actual runner](<run.sh>) and [Git identity](<identity.txt>) preserve execution details. The runner references additional reviewer fixtures retained in the outer review workspace; this directory alone is not a standalone replay kit.

Fresh immutable app archive SHA256: `af1c07934ff6f42fac7e634bda182aa44efbdc9a13ebe4a2e4cba1eb404fee06`. All three C6 files are identical to accepted36:

- Core: `1fc1190fc93cf1394397f9ad3b159b4fb4386bbca85e0bb8d4daecb733df8025`.
- Desktop adapter: `22bfa7cf3e4cf6d7ed4e72626f3d4f4dfa85db51251e0bf01a00e5f3c252db36`.
- C6 tests: `25d9caac5451175c01c6251d624a0fd0171d50616947afbfe35e84b7c24a7d27`.

The merge changes only these three files relative to ba3566. D10 localization and managed-update test repairs remain intact and passed in this combined execution, rather than merely being inferred compatible.

## History and limits

The [original be457 probe log](<historical-be457-probes.log>) is deliberately retained as negative evidence: seven Store probes plus two adapter probes passed, while direct public-field consent mutation during a busy await exposed one counterexample. No production revoke caller was found; it was adversarial contract hardening, not an established production P2. New36 adds startup-only rechecks and exact-owner protection; the combined run independently reran all twelve current probes.

The 18 skipped cases remain unexecuted: five opt-in desktop vault cases; asset provenance; a Full-build placeholder requiring Client mode; a private desktop bundle; live domain installation; two dual-stack SSH cases; two lab SSH cases; live VPS installation; Windows release asset; update-security release fixture; two update-manifest fixtures. Focused reviewer vault probes do not replace these acceptance cases.

Execution used Flutter 3.47.7 / Dart 3.13.5, offline dependencies, concurrency 1, complete assets and original analysis options, and owned source/HOME/TMP/XDG/cache under the authorized Debian archive volume. No real VPN/helper/service/UAC/OS-autostart/phone/VPS/network/security changes occurred.

This closes C6 at source/host-test level only. Native Windows, packaged Ubuntu, Android device behavior, APK provenance and release acceptance are not established. Android native sources are unchanged here, but shared Dart changed. The bundled AAR remains a separate release blocker. Apple work remains deferred.

Eight raw evidence files were copied byte-identically; no log whitespace or line-ending cleanup was performed.
