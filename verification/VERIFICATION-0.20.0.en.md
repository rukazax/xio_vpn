# XIO 0.20.0 verification

This update changes the shared Flutter UI for Android, Ubuntu, Windows and the iOS source project. Server and cryptographic implementations are unchanged.

## Changes

Help and FAQ, and Licence and responsibility moved into About XIO. Engine information is grouped under Protocols. Diagnostics and the session log moved into Connection settings.

## Verified for this build

- Flutter analyze reports no issues.
- The full Flutter test result is recorded in flutter-tests-020.log. Dedicated Russian and English navigation tests check the new hierarchy, removal of the old top-level entries, access to protocols, help and diagnostics, and back navigation.
- Thirteen translation catalogues have matching keys, placeholders and bundled-font coverage. These are structural checks, not a native-language editorial review.
- ARM64, ARMv7 and x86_64 Android APKs passed signature, launcher-alias, native-payload and 16 KiB zipalign checks. Hashes are recorded in android-release-020.json and SHA256SUMS-0.20.0.
- Ubuntu DEB and portable archives use the same network helper as 0.19. The Windows ZIP contains a newly compiled Windows AOT snapshot from the shared UI, with the previous runner and helper.
- Screenshots come from Flutter test rendering with actual fonts, in dark mode, in Russian and English.

## Limits

The physical Honor Magic V3 and native Windows networking were not tested for this update. There is no signed iOS IPA: changes are in the source project, which needs a Mac, Xcode, an Apple team and provisioning. No new VPS protocol cycle was run because networking code did not change. Earlier evidence and limits remain in VERIFICATION-0.19.0.ru.md and the historical Android 0.18 reports.

This release does not claim independent security auditing, HTTPS traffic indistinguishability, compatibility with every firmware or app-store approval.
