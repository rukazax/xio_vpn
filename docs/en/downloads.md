# Download XIO

One naming rule:
`XIO-<App>-<version>-<OS>-<arch>.<ext>`
(`Client`/`Full` В· `android`/`windows`/`ubuntu`/`ios` В· `arm64-v8a`/`armeabi-v7a`/`x86_64`/`universal`/`x64`).

## XIO Client вЂ” connect to existing servers

| System | File | Size |
|---|---|---|
| Android 8+ В· ARM64 | [XIO-Client-0.22.5-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-arm64-v8a.apk) | 22.8 MB |
| Android 8+ В· ARM32 | [XIO-Client-0.22.5-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-armeabi-v7a.apk) | 22.7 MB |
| Android 8+ В· x86-64 | [XIO-Client-0.22.5-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-x86_64.apk) | 24.0 MB |
| Android 8+ В· universal | [XIO-Client-0.22.5-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-android-universal.apk) | 66.7 MB |
| Windows 11 x64 | [XIO-Client-0.22.5-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-windows-x64.zip) | 25.1 MB |
| Ubuntu 22.04+ x64 | [XIO-Client-0.22.4-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-amd64.deb) | 0.22.4 |
| Ubuntu 22.04+ x64 | [XIO-Client-0.22.4-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-x64.tar.gz) | 0.22.4 |
| iOS | вЂ” | no IPA |

## Full XIO вЂ” your own server

| System | File | Size |
|---|---|---|
| Android 8+ В· ARM64 | [XIO-Full-0.22.5-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-arm64-v8a.apk) | 57.8 MB |
| Android 8+ В· ARM32 | [XIO-Full-0.22.5-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-armeabi-v7a.apk) | 57.8 MB |
| Android 8+ В· x86-64 | [XIO-Full-0.22.5-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-x86_64.apk) | 59.0 MB |
| Android 8+ В· universal | [XIO-Full-0.22.5-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Full-0.22.5-android-universal.apk) | 102.9 MB |
| Windows 11 x64 | [XIO-0.22.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.22.0/XIO-0.22.0-windows-x64.zip) | 0.22.0 |
| Ubuntu 22.04+ x64 | [XIO-0.22.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.22.0/XIO-0.22.0-ubuntu-amd64.deb) | 0.22.0 |
| iOS | вЂ” | none |

## Verification and metadata

- [SHA256SUMS-0.22.5.txt](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/SHA256SUMS-0.22.5.txt) вЂ” checksums for every 0.22.5 file
- [verification-0.22.5.json](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/verification-0.22.5.json) вЂ” APK verification report
- [source-inputs-0.22.5.json](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/source-inputs-0.22.5.json) вЂ” build input hashes

## Install

- **Android:** allow installs from an unknown source for your file manager, open the APK. The client
  and the full application install side by side (different packages).
- **Windows:** unpack the whole ZIP and start `XIOClient.exe` from that folder (`data/` and `libexec/`
  must sit next to it). SmartScreen warns because the app is not signed with a publisher certificate.
  Connecting needs administrator rights: the helper changes routes and DNS.
- **Ubuntu:** `sudo apt install ./XIO-Client-0.22.4-ubuntu-amd64.deb` or unpack the tar.gz. Requires
  `iproute2` and polkit.

[All releases](https://github.com/rukazax/xio_vpn/releases) В· [Compatibility 0.22.5](../compatibility/0.22.5.en.md) В· [Home](../../README.md)
