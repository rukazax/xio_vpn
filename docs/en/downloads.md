# Download XIO

> **v0.24.0 is the current release.** The [release page](https://github.com/rukazax/xio_vpn/releases/tag/v0.24.0) and the direct links below do not rely on `/latest`. Read the [limitations](../compatibility/0.24.0.en.md) before installing.

One naming rule:
`XIO-<App>-<version>-<OS>-<arch>.<ext>`

> **0.24.0 installs in place over 0.23.1.** Package names and the signer did not change, so Android updates the app and keeps profiles and settings.

## XIO Client — connect to existing servers

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.24.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-arm64-v8a.apk) | 22.9 MiB |
| Android 8+ · ARM32 | [XIO-Client-0.24.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-armeabi-v7a.apk) | 22.8 MiB |
| Android 8+ · x86-64 | [XIO-Client-0.24.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-x86_64.apk) | 24.2 MiB |
| Android 8+ · universal | [XIO-Client-0.24.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Client-0.24.0-android-universal.apk) | 67.0 MiB |

iOS is not built: it needs a Mac, Xcode and Apple signing.

## Full XIO — your own server

| System | File | Size |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.24.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-arm64-v8a.apk) | 57.9 MiB |
| Android 8+ · ARM32 | [XIO-Full-0.24.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-armeabi-v7a.apk) | 57.9 MiB |
| Android 8+ · x86-64 | [XIO-Full-0.24.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-x86_64.apk) | 59.1 MiB |
| Android 8+ · universal | [XIO-Full-0.24.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-android-universal.apk) | 103.1 MiB |
| Ubuntu 22.04+ x64 | [XIO-Full-0.24.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-ubuntu-amd64.deb) | 49.0 MiB, installs with `apt` |
| Ubuntu 22.04+ x64 | [XIO-Full-0.24.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-ubuntu-x64.tar.gz) | 57.9 MiB, portable archive |
| Windows 11 x64 | [XIO-Full-0.24.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/XIO-Full-0.24.0-windows-x64.zip) | ZIP: app, helper, Wintun |
| Server archive | [xio-server-0.24.0.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.24.0/xio-server-0.24.0.tar.gz) | 21.3 MiB, recipe 25 |

> **The Windows Client is not part of 0.24.0.** The Windows desktop client is published in 0.23.1.

## Verified in 0.24.0

- the server archive: live install on Debian 13 (LXC, `fr-host.fr`), `init` ok, recipe 25;
- XIO Full 0.24.0 on a POCO X6 5G (Android 16): in-place install over 0.23.1, profile import, RIVET/S1 connection, disconnect and reconnect;
- APK signatures and `zipalign`, the Windows build and the Ubuntu package build.

Details and hashes: `verification-0.24.0.json` on the release page.
