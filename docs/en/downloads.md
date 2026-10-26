# Download XIO

## Android 0.22.5

- [XIO Client · ARM64](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-arm64-v8a.apk)
- [XIO Client · ARM32](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-armeabi-v7a.apk)
- [XIO Client · x86-64](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-x86_64.apk)
- [XIO Client · universal](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-universal.apk)
- [SHA-256 and verification report](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/SHA256SUMS-0.22.5.txt)

## Windows x64, 0.22.5

- [XIO Client · Windows x64 ZIP](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/XIO-Client-0.22.5-windows-x64.zip)

The archive contains `XIOClient.exe`, `data/`, the `libexec/xio-tunnel.exe` helper, the official
`wintun.dll` and the licences. The application is not signed with a publisher certificate, so
Windows shows a SmartScreen warning. Connecting requires administrator rights: the helper changes
routes and DNS.

[Setup and limits](../../client/README.en.md). [Compatibility status](../compatibility/0.22.5.en.md).

[Русский](../ru/downloads.md) · [Home](../../README.md)

## Earlier builds

| Build | Download |
|---|---|
| Android ARM64, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-arm64-v8a.apk) |
| Android ARM32, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-armeabi-v7a.apk) |
| Android x86_64, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-x86_64.apk) |
| Android universal, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-universal.apk) |
| Windows x64 · ZIP, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-windows-x64.zip) |
| Ubuntu x64 · DEB, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-amd64.deb) |
| Ubuntu x64 · tar.gz, 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-Client-0.22.4-ubuntu-x64.tar.gz) |
| Sources 0.22.4 | [GitHub](https://github.com/rukazax/xio_vpn/releases/download/v0.22.4/XIO-0.22.4-source.zip) |

[All releases](https://github.com/rukazax/xio_vpn/releases)

Android requires Android 8+. Ubuntu: 22.04+ x64. There is no iOS IPA: that needs a Mac, Xcode and an
Apple signing setup. The 0.22.5 Windows build was verified natively on Windows 11 x64: the
AmneziaWG tunnel comes up and traffic flows. Xray does not connect in this build — a known
limitation, see the compatibility page.
