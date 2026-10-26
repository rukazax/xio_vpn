# XIO — X in, 1 out

XIO is a VPN system with its own server and two applications: **XIO Client** connects to existing
servers, and **full XIO** deploys and maintains the server. One server serves several transports at
once; the client imports a single portable `xio://` profile and picks the transport itself.

[Download](#download) · [How it works](#how-it-works) · [Protocols](#protocols) · [How we test](#how-we-test) · [Русский](README.ru.md)

## Two applications

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

<p><img src="docs/images/2026-10-26-full-home.png" width="420" alt="Full XIO home"> <img src="docs/images/2026-10-26-full-connection.png" width="420" alt="Full XIO connection screen"></p>
<p><img src="docs/images/2026-10-26-full-settings.png" width="420" alt="Full XIO settings"></p>

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

| Transport | Basis | Network transport | Purpose | Android | Windows | Ubuntu | iOS |
|---|---|---|---|---|---|---|---|
| **AWG** | AmneziaWG (WireGuard + obfuscation) | UDP | fast everyday tunnel | ✅ | ✅ | ✅ | — |
| **RIVET/H3** | in-house | QUIC / HTTP/3 + TLS 1.3 | resilient access where suspicious TLS is filtered | ✅ | ✅ | ✅ | ✅ |
| **RIVET/S1** | in-house | TCP + TLS 1.3 | the same tunnel for UDP-blocked networks | ✅ | ✅ | ✅ | ✅ |
| **Xray/REALITY** | Xray (VLESS + REALITY) | TCP, masquerades as a real TLS site | camouflage as a genuine site | ✅ | ⚠️ | ⚠️ | — |
| **OpenVPN/Cloak** | OpenVPN inside Cloak | TCP + TLS obfuscation | last resort in strict networks | ✅ | — | — | — |

✅ engine present and tested; ⚠️ declared but does not connect on the 0.22.5 client/gateway pair
(see limitations); — not available.

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

One naming rule: `XIO-<App>-<version>-<OS>-<arch>.<ext>`, where app is `Client` or `Full`, OS is
`android`, `windows`, `ubuntu`, `ios`, and arch is `arm64-v8a`, `armeabi-v7a`, `x86_64`, `universal`,
`x64`.

### XIO Client — connect to existing servers

| System | File | What it is |
|---|---|---|
| Android 8+ · ARM64 | `XIO-Client-0.22.5-android-arm64-v8a.apk` | the usual choice for modern phones |
| Android 8+ · ARM32 | `XIO-Client-0.22.5-android-armeabi-v7a.apk` | older 32-bit devices |
| Android 8+ · x86-64 | `XIO-Client-0.22.5-android-x86_64.apk` | emulators and x86 tablets |
| Android 8+ · universal | `XIO-Client-0.22.5-android-universal.apk` | one build for all architectures |
| Windows 11 x64 | `XIO-Client-0.22.5-windows-x64.zip` | ZIP: app, helper, Wintun |
| Ubuntu 22.04+ x64 | `XIO-Client-0.22.4-ubuntu-amd64.deb` | 0.22.4 DEB (not rebuilt in 0.22.5) |
| Ubuntu 22.04+ x64 | `XIO-Client-0.22.4-ubuntu-x64.tar.gz` | 0.22.4 tar.gz |
| iOS | — | no IPA: needs a Mac, Xcode and Apple signing |

Everything lives in [Releases](https://github.com/rukazax/xio_vpn/releases/tag/v0.22.5): 0.22.5
builds, [checksums](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/SHA256SUMS-0.22.5.txt),
[verification report](https://github.com/rukazax/xio_vpn/releases/download/v0.22.5/verification-0.22.5.json).

### Full XIO — your own server

| System | File | What it is |
|---|---|---|
| Android 8+ · ARM64 | `XIO-Full-0.22.5-android-arm64-v8a.apk` | full application with administration |
| Android 8+ · ARM32 | `XIO-Full-0.22.5-android-armeabi-v7a.apk` | older 32-bit devices |
| Android 8+ · x86-64 | `XIO-Full-0.22.5-android-x86_64.apk` | emulators |
| Android 8+ · universal | `XIO-Full-0.22.5-android-universal.apk` | one build for all architectures |
| Windows 11 x64 | `XIO-Full-0.22.5-windows-x64.zip` | ZIP: app, helper, Wintun |
| Ubuntu 22.04+ x64 | `XIO-0.22.0-ubuntu-amd64.deb` | 0.22.0 build |
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

More: [methodology and criteria](docs/compatibility/0.22.5.en.md) ·
[latest run report](docs/blog/2026-10-26-windows-and-ipv6.en.md).

## Screenshots

Client UI renders (dark and light):

<p><img src="docs/images/client-0.22.4-dark.png" width="230" alt="Client, dark theme"> <img src="docs/images/client-0.22.4-light.png" width="230" alt="Client, light theme"></p>

Windows client, real run on 2026-10-26:

<p><img src="docs/images/2026-10-26-win-windows-home.png" width="420" alt="Windows client home"> <img src="docs/images/2026-10-26-win-windows-profile.png" width="420" alt="Windows client with an imported profile"></p>

## Limitations

- **Xray/REALITY does not connect** on the 0.22.5 client with the Xray 26.7.28 gateway: the REALITY
  implementation in the client core is incompatible. AWG and RIVET work.
- **Public IPv6** is unverified. The stand used a local ULA prefix, and IPv6 egress from the tunnel is
  blocked by the server on purpose.
- **iOS** is not built: no Mac/Xcode/iPhone, no IPA.
- **Full protocol parity is not achieved**: Android has 5 transports, Windows/Ubuntu 4, iOS 2.
- **Alongside another VPN** XIO does not work: the `/1` routes conflict.
- The Windows application is not signed with a publisher certificate, so SmartScreen warns.

## Documentation

- [Compatibility and status 0.22.5](docs/compatibility/0.22.5.en.md)
- [Download](docs/en/downloads.md) · [Build from source](docs/en/build.md) · [FAQ](docs/en/faq.md)
- [Protocol documentation](docs/protocols/README.md) · [RIVET](RIVET-IMPLEMENTATION-0.2.ru.md)
- [Changelog](CHANGELOG.md) · [License GPL-3.0-only](LICENSE)

Original code is GPL-3.0-only. Third-party components keep their own licences:
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
