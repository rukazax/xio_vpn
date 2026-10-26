# Download XIO

One naming rule:
`XIO-<App>-<version>-<OS>-<arch>.<ext>`



> **0.23.0 installs as a separate application.** The packages were renamed (`app.xio.client`, `app.xio.xio`), so Android will not update the previous build in place: export/import your profiles and remove the old version manually. Legacy `x1o://` profiles still import.

## XIO Client — connect to existing servers

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-arm64-v8a.apk) | 22.8 MB |
| Android 8+ · ARM32 | [XIO-Client-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-armeabi-v7a.apk) | 22.7 MB |
| Android 8+ · x86-64 | [XIO-Client-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-x86_64.apk) | 24.0 MB |
| Android 8+ · universal | [XIO-Client-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-universal.apk) | 66.7 MB |
| Windows 11 x64 | [XIO-Client-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-windows-x64.zip) | 25.1 MB |
| iOS | — | no IPA |

## Full XIO — your own server

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-arm64-v8a.apk) | 57.8 MB |
| Android 8+ · ARM32 | [XIO-Full-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-armeabi-v7a.apk) | 57.8 MB |
| Android 8+ · x86-64 | [XIO-Full-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-x86_64.apk) | 59.0 MB |
| Android 8+ · universal | [XIO-Full-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-universal.apk) | 102.9 MB |
| Windows 11 x64 | [XIO-Full-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-windows-x64.zip) | 60.2 МБ |
| iOS | — | none |

## Verification and metadata

- [SHA256SUMS-0.23.0.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/SHA256SUMS-0.23.0.txt) — checksums for every 0.23.0 file
- [verification-0.23.0.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/verification-0.23.0.json) — APK verification report
- [source-inputs-0.23.0.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/source-inputs-0.23.0.json) — build input hashes

## Install

- **Android:** allow installs from an unknown source for your file manager, open the APK. The client
  and the full application install side by side (different packages).
- **Windows:** unpack the whole ZIP and start `XIOClient.exe` from that folder (`data/` and `libexec/`
  must sit next to it). SmartScreen warns because the app is not signed with a publisher certificate.
  Connecting needs administrator rights: the helper changes routes and DNS.
  `iproute2` and polkit.

[All releases](https://github.com/rukazax/xio_vpn/releases) · [Compatibility 0.23.0](../compatibility/0.23.0.en.md) · [Home](../../README.md)
