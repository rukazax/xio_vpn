<p align="center">
  <a href="https://github.com/rukazax/xio_vpn">
    <img src="docs/images/logo.png" alt="XIO" width="120">
  </a>
</p>

<p align="center">Your VPN, your servers, one interface. Android · Windows · Ubuntu · iOS.</p>

<p align="center">
  <a href="https://github.com/rukazax/xio_vpn/releases/tag/v0.23.0"><img alt="release" src="https://img.shields.io/github/v/release/rukazax/xio_vpn?include_prereleases&style=flat-square&label=release" /></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square" /></a>
  <a href="https://github.com/rukazax/xio_vpn/releases/tag/v0.23.0"><img alt="platforms" src="https://img.shields.io/badge/platform-Android%20%7C%20Windows%20%7C%20Ubuntu%20%7C%20iOS-lightgrey?style=flat-square" /></a>
  <a href="#how-it-works"><img alt="how it works" src="https://img.shields.io/badge/docs-how%20it%20works-informational?style=flat-square" /></a>
  <a href="docs/compatibility/0.22.5.en.md"><img alt="compatibility" src="https://img.shields.io/badge/docs-compatibility-informational?style=flat-square" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.ru.md">Русский</a>
</p>

XIO is a VPN system with its own server and two applications: **XIO Client** connects to existing
servers, and **full XIO** deploys and maintains the server. One server serves several transports at
once; the client imports a single portable `xio://` profile and picks the transport itself.

[Download](#download) · [How it works](#how-it-works) · [Protocols](#protocols) · [How we test](#how-we-test) · [Русский](README.ru.md)

## Two applications

> **0.23.0 installs as a separate application.** The packages were renamed (`app.xio.client`, `app.xio.xio`), so Android will not update the previous build in place: export/import your profiles and remove the old version manually. Legacy `x1o://` profiles still import.


| | **XIO Client** | **Full XIO** |
|---|---|---|
| Purpose | connect to servers that already exist | install and maintain your own server |
| Styling | amber/orange | green |
| Installation | separate package next to the full app | separate package next to the client |
| Rights | no SSH/root/admin; only a scoped token for its own subclients when granted | SSH provisioning, user issue/revoke, quotas, batch export |
| Storage | separate from the full application | its own |

The client installs alongside the full application and never receives server keys.

## The full application: your own server

Full XIO administers a server; it is not for connecting to somebody else's. Over SSH it checks the
machine, installs the server package, issues and revokes users, accounts traffic and updates
components. The client does not need the full application to work.

```mermaid
flowchart LR
  A["Full XIO"] -->|"1. SSH check<br/>OS, systemd, /dev/net/tun"| V["VPS"]
  A -->|"2. install the package"| S["Server services<br/>AWG · RIVET · Xray · Cloak"]
  A -->|"3. users, quotas, revoke"| S
  S -->|"4. xio:// profiles"| C["XIO Client"]
  S --> N["Internet"]
```

What it does:

- checks the server before installing: OS, x86_64, systemd, `/dev/net/tun`, busy ports;
- installs the server package from its own bundle and starts the services (AmneziaWG, RIVET, Xray,
  Cloak);
- issues users and profiles, enforces quotas and revokes access;
- shows service state, per-user traffic and secret-free logs;
- updates the server and rolls changes back.

Screenshots of the full application (Windows, 2026-10-26):

<p><img src="docs/images/2026-10-26-full-home.png" width="250" alt="Full XIO home"> <img src="docs/images/2026-10-26-full-connection.png" width="250" alt="Full XIO connection"> <img src="docs/images/2026-10-26-full-settings.png" width="250" alt="Full XIO settings"></p>

The window is compact (430×800), phone-sized: the same screen without stretching across the width.

## How it works

```mermaid
flowchart LR
  subgraph Device["Device"]
    UI["Application<br/>Flutter UI"] -->|"xio:// profile"| STORE[("Local<br/>storage")]
    UI --> ENG["Platform engine"]
  end
  ENG -->|"Android: VpnService<br/>Windows/Linux: helper + TUN"| TUN["Tunnel"]
  TUN -->|"one transport"| SRV["XIO server"]
  SRV --> NET["Internet"]
  ADMIN["Full XIO"] -->|"SSH provisioning"| SRV
```

Step by step:

1. **Import.** The administrator issues an `xio://` file: a base64 container with the user, the
   server and per-transport configurations. It is stored encrypted locally (Keystore on Android,
   DPAPI on Windows, AES-GCM with file permissions on Linux).
2. **Transport choice.** The profile lists which transports really exist for that server. If the
   platform has no engine for one of them, the client says so instead of silently substituting another.
3. **Connect.** The client brings up a TUN interface, takes an address inside the tunnel and routes
   traffic through the chosen transport. Android uses the system `VpnService`; Windows and Linux use a
   separate helper that changes routes only after consent.
4. **Verify.** Once the interface is up, the client opens the selected HTTPS site through the tunnel.
   If the check fails, the connection is dropped. “Interface active” without passing traffic is not a
   success.
5. **Run.** The server accepts the traffic, assigns an internal address and NATs to the internet.

## Protocols

XIO does not reinvent everything: some transports build on proven implementations, one is our own.
Different transports solve different problems: speed, censorship resistance, and networks where UDP
is closed.

| Transport | Basis | Network transport | Purpose | Android | Windows | Ubuntu | iOS | Where and when verified |
|---|---|---|---|---|---|---|---|---|
| **AWG** | AmneziaWG (WireGuard + obfuscation) | UDP | fast everyday tunnel | yes | yes | yes | — | Android POCO X6 — 2026-10-26, server 81.177.142.37; Debian 13 — 2026-10-26, same server; Windows — native run on 0.22.5, on 0.23.0 the connect fails at the firewall step (see limitations) |
| **RIVET/H3** | in-house | QUIC / HTTP/3 + TLS 1.3 | resilient access where suspicious TLS is filtered | yes | yes* | yes* | yes* | Android — 2026-10-26, local stand 192.168.88.17:8443 (RIVET/H3 and RIVET/S1); Windows and Ubuntu — engine built, no native run; iOS not built |
| **RIVET/S1** | in-house | TCP + TLS 1.3 | the same tunnel for UDP-blocked networks | yes | yes* | yes* | yes* | same as above |
| **Xray/REALITY** | Xray (VLESS + REALITY) | TCP, masquerades as a real TLS site | camouflage as a genuine site | yes | yes* | yes* | — | Android 0.22.3 — PASS; 0.23.0 client with Xray 26.7.28 gateway does not connect (see limitations) |
| **OpenVPN/Cloak** | OpenVPN inside Cloak | TCP + TLS obfuscation | last resort in strict networks | yes | — | — | — | Android — 2026-10-21, checked together with the other four transports |

`yes` — engine present and a native run on this platform was performed (when and where — last column);
`yes*` — engine present in source and build, no native run on this platform;
`—` — not available.

### What RIVET is

RIVET is our own development. The idea: give the client two independent “entrances” to the same
server, so blocking one does not kill access.

```mermaid
flowchart LR
  C["Client"] -->|"H3: QUIC 8443/udp<br/>S1: TCP 8443/tcp"| E["RIVET entry"]
  E -->|"pin / gatewayId check<br/>user credentials"| G["RIVET gateway"]
  G --> IP["Internal address 10.79.0.N<br/>traffic accounting"]
  G --> NET["Internet"]
```

- Two transports (**H3** and **S1**) share one authentication, so the client can switch without
  changing the profile.
- The gateway certificate is pinned (`pin`); every server has its own `gatewayId` and outer CA.
- A user gets a `secret` and an `entryToken`; the parent token is never passed to a subclient.
- Internal addressing is `10.79.0.N` with per-user traffic accounting.

## Download

> **v0.23.0 is a pre-release.** The links below download files from this tagged release. Read the [limitations](#limitations) before installing.

One naming rule: `XIO-<App>-<version>-<OS>-<arch>.<ext>`. App is `Client` or `Full`; OS is
`android`, `windows` or `ubuntu`; architecture is `arm64-v8a`, `armeabi-v7a`, `x86_64`,
`universal`, `amd64` or `x64`.

### XIO Client — connect to existing servers

| System | File | What it is |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Client-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-arm64-v8a.apk) | the usual choice for modern phones |
| Android 8+ · ARM32 | [XIO-Client-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-armeabi-v7a.apk) | older 32-bit devices |
| Android 8+ · x86-64 | [XIO-Client-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-x86_64.apk) | emulators and x86 tablets |
| Android 8+ · universal | [XIO-Client-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-android-universal.apk) | one build for all architectures |
| Windows 11 x64 | [XIO-Client-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-windows-x64.zip) | ZIP: app, helper, Wintun |
| Ubuntu 22.04+ x64 | [XIO-Client-0.23.0-ubuntu-amd64.deb](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-ubuntu-amd64.deb) | DEB package |
| Ubuntu 22.04+ x64 | [XIO-Client-0.23.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Client-0.23.0-ubuntu-x64.tar.gz) | TAR.GZ archive |
| iOS | — | no IPA: needs a Mac, Xcode and Apple signing |

Everything lives in [Releases](https://github.com/rukazax/xio_vpn/releases/tag/v0.23.0): 0.23.0
builds, [checksums](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/SHA256SUMS-0.23.0.txt),
[verification report](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/verification-0.23.0.json).

### Full XIO — your own server

| System | File | What it is |
|---|---|---|
| Android 8+ · ARM64 | [XIO-Full-0.23.0-android-arm64-v8a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-arm64-v8a.apk) | full application with administration |
| Android 8+ · ARM32 | [XIO-Full-0.23.0-android-armeabi-v7a.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-armeabi-v7a.apk) | older 32-bit devices |
| Android 8+ · x86-64 | [XIO-Full-0.23.0-android-x86_64.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-x86_64.apk) | emulators |
| Android 8+ · universal | [XIO-Full-0.23.0-android-universal.apk](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-android-universal.apk) | one build for all architectures |
| Windows 11 x64 | [XIO-Full-0.23.0-windows-x64.zip](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-windows-x64.zip) | ZIP: app, helper, Wintun |
| Ubuntu 22.04+ x64 | [XIO-Full-0.23.0-ubuntu-x64.tar.gz](https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-ubuntu-x64.tar.gz) | TAR.GZ archive |
| iOS | — | none |

The server is installed from the full application over SSH on Debian 12/13, Ubuntu 22.04/24.04/26.04,
RHEL/Alma/Rocky 9/10 (x86_64, systemd, `/dev/net/tun`).

## How to connect

1. Get an `xio://` profile from the server administrator.
2. Install **XIO Client** (not the full application — that one is for running servers).
3. Open the app → “Add profile” → paste the key or pick the file.
4. Press “Connect”. Android asks for VPN permission once; Windows asks for administrator rights for
   the helper.
5. Make sure “Site reachable · HTTP 200” appears and traffic counters grow.

Android screens are not published: the app sets `FLAG_SECURE`, so the system returns a black image.
That is protection, not a bug.

## How we test

The methodology rests on one rule: **only an observed result on real hardware counts as evidence, not
a successful build.**

```mermaid
flowchart LR
  S1["1. Static<br/>analyze, unit tests"] --> S2["2. Artifacts<br/>signature, ABI, 16 KB"]
  S2 --> S3["3. Stand<br/>server + real network"]
  S3 --> S4["4. Device<br/>physical phone/PC"]
  S4 --> S5["5. Independent check<br/>traffic, gateway ping, counters"]
  S5 --> S6["6. Report and release"]
```

| Level | What is checked | What it is not |
|---|---|---|
| Static | `flutter analyze`, unit/widget tests, Go tests, transport parity gate | does not prove networking |
| Artifacts | APK signature, `package`/`versionCode`, ABI and 16 KB alignment of the native payload | does not prove a connection |
| Stand | the server is installed from the shipped bundle and a client connects over a real network | does not prove phone behaviour |
| Device | install on a physical Android device / run on Windows | does not prove the route |
| Independent check | HTTPS check inside the tunnel, `ping` to the tunnel gateway, server counters and `endpoint` | — |

Rules we keep:

- “Interface active” without passing traffic is not a success.
- Cross-builds, Wine, emulators and unit tests do not replace checks on Windows, physical Android or
  Ethernet.
- `FAIL`, `BLOCKED` and `NOT_EXECUTED` are written as such and never replaced with “works”.
- Every run stores version, commit, device, commands and results separately from previous runs.

More: [methodology and criteria](docs/compatibility/0.23.0.en.md) ·
[latest run report](docs/blog/2026-10-26-windows-and-ipv6.en.md).

## Screenshots

Client UI renders (dark and light):

<p><img src="docs/images/client-0.22.4-dark.png" width="230" alt="Client, dark theme"> <img src="docs/images/client-0.22.4-light.png" width="230" alt="Client, light theme"></p>

Windows client, real run on 2026-10-26:

<p><img src="docs/images/2026-10-26-win-windows-home.png" width="300" alt="XIO Client for Windows home"></p>

## Limitations

- **Xray/REALITY does not connect** on the 0.23.0 client with the Xray 26.7.28 gateway: the REALITY
  implementation in the client core is incompatible. AWG and RIVET work.
- **Windows 0.23.0: connect fails at the firewall step** — the helper runs elevated, the server
  handshake succeeds, but `netsh` inside the helper returns an error (`Windows VPN firewall setup
  failed`) and the client rolls the connection back. The same command run manually succeeds. The
  defect is known and being fixed; RIVET and Xray cannot be verified on Windows because the firewall
  step is shared by every transport.
- **Ubuntu 0.23.0: the GUI client does not create a window** (the process lives, the Impeller/EGL
  surface never comes up). The tunnel itself works through `libexec/xio-tunnel`, but requires
  `systemd-resolved`: without it the connect is rejected with `systemd-resolved could not configure
  VPN DNS`.
- **A full tunnel on Linux cuts off the local network**: while the tunnel is up the machine stops
  answering SSH from the LAN, because all unmarked IPv4 goes into the tunnel.
- **Public IPv6** is unverified. The stand used a local ULA prefix, and IPv6 egress from the tunnel is
  blocked by the server on purpose.
- **iOS** is not built: no Mac/Xcode/iPhone, no IPA.
- **Full protocol parity is not achieved**: Android has 5 transports, Windows/Ubuntu 4, iOS 2.
- **Alongside another VPN** XIO does not work: the `/1` routes conflict.
- The Windows application is not signed with a publisher certificate, so SmartScreen warns.

## Documentation

- [Compatibility and status 0.23.0](docs/compatibility/0.23.0.en.md)
- [Download](docs/en/downloads.md) · [Build from source](docs/en/build.md) · [FAQ](docs/en/faq.md)
- [Protocol documentation](docs/protocols/README.md) · [RIVET](RIVET-IMPLEMENTATION-0.2.ru.md)
- [Changelog](CHANGELOG.md) · [License GPL-3.0-only](LICENSE)

Original code is GPL-3.0-only. Third-party components keep their own licences:
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
