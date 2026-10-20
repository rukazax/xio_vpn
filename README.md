# XIO — X in 1 out

> **Android patch 0.22.1:** fixes new Cloak user activation and includes server package revision 20. [Downloads and notes](https://github.com/rukazax/xio_vpn/releases/tag/v0.22.1) · [Physical Android report](docs/verification/android-physical-2026-10-21.en.md). Desktop packages remain at 0.22.0.

📱 [Physical Android tests: five protocols, the Cloak fix, and the results](docs/blog/2026-10-21-physical-android.en.md)

**English** · [Русский](README.ru.md)

<img src="docs/images/logo.png" alt="XIO" width="96">

Your VPN, your servers, one interface. Connect a VPS, import supported configurations, create users and share access. When an attempt times out, XIO tries the next available configuration for that user.

[Download](docs/en/downloads.md) · [Guide](docs/en/guide.md) · [Protocols](docs/en/protocols.md) · [Build](docs/en/build.md) · [FAQ](docs/en/faq.md)

![XIO](docs/images/overview.svg)

## Features

- SSH installation and maintenance of your VPS, user management, revocation and export.
- Automatic detection of supported third-party configuration formats.
- Protocol priority, attempt timeout and HTTPS test; youtube.com is the default.
- Multi-protocol user bundles and delegated administration with active-user limits.
- Android split tunnelling, system theme, icon choices, quick-settings tile and 13 languages.
- VPN tethering on rooted Android; experimental Windows ICS integration with administrator rights.
- Signed client-update metadata and managed-server maintenance with rollback.

## Version 0.22 builds

| Platform | Availability | Client protocols |
|---|---|---|
| Android 8+ | ARM64, ARMv7, x86_64 APKs; ARM64 physically checked on one POCO X6 5G | Xray, RIVET/S1, RIVET/H3, AWG, Cloak |
| Ubuntu x64 | DEB and portable archive; system tests on Ubuntu 24.04 | Xray, RIVET/S1, RIVET/H3, AWG |
| Windows 10/11 x64 | Test ZIP; UI tested in Wine, native driver and ICS still need a Windows test | Xray, RIVET/S1, RIVET/H3, AWG |
| iPhone/iPad | Xcode source project, no signed IPA | RIVET/S1/H3 in source; Apple validation pending |

**Protocols is under Settings → Connection**. Help and licensing remain under About XIO. Standalone WireGuard, OpenVPN, IKEv2, Shadowsocks and Tailscale are removed; OpenVPN remains an internal Cloak dependency.

## What a VPN cannot promise 🔎

The ISP can observe the entry IP even with TLS. A strict allowlist requires reachable ingress; changing a website name alone cannot reach a blocked VPS. This build has not been field-tested on Russian operator networks. RIVET is experimental, without an independent audit or proven browser indistinguishability.

![Network limits](docs/images/allowlist-entry-en.svg)

[Changes and reasoning](docs/blog/2026-10-19-restricted-networks.md#english) · [Video review and primary sources](docs/research/2026-10-19-video-protocols.en.md) · [Releases](https://github.com/rukazax/xio_vpn/releases)

Owned code: [GPL-3.0-only](LICENSE). Dependencies keep their licences: [0.22 notices](THIRD-PARTY-0.22.md). Copyright: Константин Александрович Ерёмин, er-ka@mail.ru. [Support XIO](https://x1o.org/pay).
