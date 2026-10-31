# Download XIO

> **v0.23.1 is a pre-release.** The [release page](https://github.com/rukazax/xio_vpn/releases/tag/v0.23.1) and direct links below do not rely on `/latest`. Check the [limitations](../compatibility/0.23.1.en.md) before installing.

One naming rule:
`XIO-<App>-<version>-<OS>-<arch>.<ext>`

> **0.23.1 installs in place over 0.23.0.** Package names did not change, so Android updates the app and keeps profiles and settings.

## XIO Client — connect to existing servers

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.1-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-arm64-v8a.apk) | 22.9 MiB |
| Android 8+ · ARM32 | [XIO-Client-0.23.1-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-armeabi-v7a.apk) | 22.8 MiB |
| Android 8+ · x86-64 | [XIO-Client-0.23.1-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-x86_64.apk) | 24.2 MiB |
| Android 8+ · universal | [XIO-Client-0.23.1-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Client-0.23.1-android-universal.apk) | 67.0 MiB |

iOS is not built: it needs a Mac, Xcode and Apple signing.

## Full XIO — your own server

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.1-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-arm64-v8a.apk) | 57.9 MiB |
| Android 8+ · ARM32 | [XIO-Full-0.23.1-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-armeabi-v7a.apk) | 57.9 MiB |
| Android 8+ · x86-64 | [XIO-Full-0.23.1-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-x86_64.apk) | 59.2 MiB |
| Android 8+ · universal | [XIO-Full-0.23.1-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-android-universal.apk) | 103.1 MiB |
| Windows 11 x64 | [XIO-Full-0.23.1-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-windows-x64.zip) | ZIP: app, helper, Wintun |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.1-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-ubuntu-amd64.deb) | 49.1 MiB |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.1-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/XIO-Full-0.23.1-ubuntu-x64.tar.gz) | 57.9 MiB |
| Server package | [xio-server-0.23.1.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/xio-server-0.23.1.tar.gz) | 21.3 MiB, server payload for a Linux host |

Ubuntu packages (`.deb`/`.tar.gz`) are not part of 0.23.1: they need a Linux toolchain and are built separately. The 0.23.0 packages remain in the [previous release](https://github.com/rukazax/xio_vpn/releases/tag/v0.23.0).

## Verifying files

- [SHA256SUMS-0.23.1.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/SHA256SUMS-0.23.1.txt) — checksums for every 0.23.1 file
- [verification-0.23.1.json](https://github.com/rukazax/xio_vpn/releases/download/v0.23.1/verification-0.23.1.json) — build verification report
- [release-notes-0.23.1.md](https://github.com/rukazax/xio_vpn/blob/main/docs/release-notes-0.23.1.md) — what changed

Verify locally: `sha256sum -c SHA256SUMS-0.23.1.txt` (Linux/macOS) or `Get-FileHash <file> -Algorithm SHA256` (Windows).

## Installing

- **Android:** open the APK; Android 8+ asks for permission to install from this source. The update installs over 0.23.0 and keeps profiles.
- **Windows:** unpack the ZIP and run `XIO.exe`. The helper (`libexec\xio-tunnel.exe`) starts elevated — it needs that to create the network interface.
- The connection check in 0.23.1 does not need an external site: the tunnel is confirmed by a fresh exchange, counters and DNS through the tunnel. The site probe is enabled separately in Settings.

[All releases](https://github.com/rukazax/xio_vpn/releases) · [Compatibility 0.23.1](../compatibility/0.23.1.en.md) · [Home](../../README.md)
