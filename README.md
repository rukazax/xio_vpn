<p align="center">
  <a href="https://github.com/rukazax/xio_vpn">
    <img src="docs/images/logo.png" alt="XIO" width="128">
  </a>
</p>

<h1 align="center">XIO</h1>

<p align="center"><b>X in, 1 out.</b> Your VPN, your servers, one interface.</p>

<p align="center">Android &middot; Windows 11 &middot; Ubuntu &middot; Linux server &middot; five transports &middot; IPv4 + IPv6</p>

<p align="center">
  <a href="https://github.com/rukazax/xio_vpn/releases"><img alt="release" src="https://img.shields.io/github/v/release/rukazax/xio_vpn?include_prereleases&style=flat-square&label=release" /></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square" /></a>
  <a href="#clients-by-platform"><img alt="platforms" src="https://img.shields.io/badge/platform-Android%20%7C%20Windows%20%7C%20Ubuntu%20%7C%20iOS-lightgrey?style=flat-square" /></a>
  <a href="#five-transports"><img alt="transports" src="https://img.shields.io/badge/transports-5-brightgreen?style=flat-square" /></a>
  <a href="#ipv4-and-ipv6"><img alt="dual stack" src="https://img.shields.io/badge/network-IPv4%20%2B%20IPv6-informational?style=flat-square" /></a>
  <a href="docs/compatibility/0.24.0.en.md"><img alt="compatibility" src="https://img.shields.io/badge/docs-compatibility-informational?style=flat-square" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.ru.md">Русский</a>
</p>

XIO is a self-hosted VPN system in three parts. **XIO Client** connects to servers that already
exist. **Full XIO** deploys and maintains your own server over SSH. The **server payload** serves
five transports at once. One portable `xio://` profile carries every transport the server offers;
the client picks the one that works on the current network and switches without a new profile.

No subscription, no account on someone else's backend, no built-in server catalogue. You bring a
VPS, XIO brings the rest.

[What this is](#what-this-is) &middot; [Features](#features) &middot; [Transports](#five-transports) &middot;
[IPv4 and IPv6](#ipv4-and-ipv6) &middot; [Cascade](#cascade-two-servers-ipv4--ipv6) &middot; [Install a server](#install-a-server) &middot;
[Clients](#clients-by-platform) &middot; [Split tunnelling](#split-tunnelling) &middot; [Security](#security) &middot;
[FAQ](#faq) &middot; [Limitations](#limitations-what-is-not-verified) &middot; [Русский](README.ru.md)

---

## Current state: 0.24.10+5027 (17 Nov 2026)

The phone → Russian VPS → foreign VPS cascade is built, deployed and verified on live servers,
and automatic failover between routes works again: when the first candidate does not come up the
app connects the next one and publishes the accepted choice. The client no longer offers
OpenVPN/Cloak; the server payload and the sections below still describe the full 0.24.0–0.24.2
set, including those transports.

0.24.9–0.24.10 change one message, not the routing: with the tunnel up, connection settings now say “the tunnel is active, disconnect the VPN first” instead of claiming another operation is still running, and name settings rather than only the mode.

| Check | Result |
|---|---|
| Bridge | `81.177.142.37` (RU, Debian 12), `xio-cascade-bridge` active |
| Exit | `103.102.135.124` (FR), `xio-cascade-exit` active, NAT44/NAT66 |
| Tunnel | SSH TUN `10.250.0.1 ⇄ 10.250.0.2`, ping 50.8 ms |
| Phone egress | IPv4 `103.102.135.124`, IPv6 `2a0c:b641:1a0:800::2a2`; direct xray exits `81.177.142.37` |
| Tests | `flutter test`: 1163 passed, 27 skipped, 0 failed |
| Analyse | `flutter analyze`: 0 errors |
| APK | `XIO-Full-0.24.10-android-arm64-v8a.apk` (release v0.24.10), arm64 + armeabi-v7a |

Commands and numbers: [CASCADE-ANDROID-RU-FR-20261117.md](docs/CASCADE-ANDROID-RU-FR-20261117.md) ·
[ANDROID-VALIDATION-20261117.md](docs/ANDROID-VALIDATION-20261117.md) ·
[screenshots](docs/screenshots/README.md) · [CHANGELOG](CHANGELOG.md).

**Known limits, not hidden:**

- there is no single button that installs the cascade on both servers; bridge and exit are
  installed as separate steps (`deploy/cascade/native/`);
- automatic failover is verified against a closed port and against a stopped AWG service;
  when every candidate is dead the round still ends with one honest error;
- the bridge–exit link is an SSH TUN (TCP-over-TCP), not WireGuard: the WireGuard handshake
  succeeds but transport packets are lost; BBR is enabled on the bridge, not on the exit;
- the mobile profile uses `9.9.9.9` for DNS, not the carrier resolver;
- Yandex Browser on the test phone renders a blank page while the tunnel works; Chrome works.
  This is browser behaviour, not the cascade;
- verified in this run: import, connection, cascade, IPv4/IPv6 egress and the main screen.
  Xray/RIVET, Wi-Fi ↔ LTE switching and a long soak after BBR were not re-checked.

---

## What this is

| Part | What it does | Runs on |
|---|---|---|
| **XIO Client** | Imports `xio://`, chooses a transport, brings up the tunnel, verifies traffic. No SSH, no server keys. | Android 8+, Windows 11 x64, Ubuntu 22.04+ |
| **Full XIO** | SSH preflight, install, update and removal of the server; users, quotas, revocation, traffic. | Android, Windows, Ubuntu |
| **Server payload** | AmneziaWG, RIVET, Xray, Cloak, OpenVPN, counters, firewall, dual-stack routing. | Linux x86_64 VPS with systemd and `/dev/net/tun` |

![XIO architecture](docs/images/xio-architecture-en.svg)

Five steps from a profile to traffic:

1. **Import.** The administrator issues an `xio://` file: a base64 container with the user, the
   server and per-transport configurations. It is stored encrypted: Android Keystore (excluded
   from backups), Windows DPAPI, Ubuntu AES-GCM with file permissions, iOS Keychain.
2. **Choose.** The profile lists the transports that really exist for that server. If the platform
   has no engine for one of them, the client says so instead of silently substituting another.
3. **Connect.** The client creates a TUN interface, takes an address inside the tunnel and routes
   traffic through the chosen transport. Android uses the system `VpnService`; Windows and Ubuntu
   use a separate privileged helper that changes routes only after consent.
4. **Verify.** The tunnel is confirmed by a fresh exchange, growing counters and a DNS lookup
   through the tunnel. The HTTPS site probe is optional and off by default.
5. **Run.** The server accepts the traffic, assigns an internal address and NATs it to the internet.

```mermaid
flowchart LR
  subgraph DEV["Device · Android / Windows 11 / Ubuntu"]
    direction TB
    UI["Flutter UI<br/>dark and light themes"]
    PROF["xio:// profile<br/>Keystore · DPAPI · AES-GCM"]
    ENG["TUN + engine<br/>transport priority and fallback"]
  end

  subgraph FULL["Full XIO · your own server"]
    direction TB
    SSH["SSH + host key pin"]
    USERS["users, quotas, revocation"]
    UPD["update and rollback"]
  end

  subgraph VPS["VPS Linux x86_64 · systemd"]
    direction TB
    BOOT["bootstrap.sh<br/>SHA-256 before unpacking"]
    UNITS["systemd units xio-*<br/>start / stop / restart"]
    RIVET["RIVET entry + gateway<br/>8443/tcp + 8443/udp"]
    AWG["AmneziaWG<br/>51821/udp"]
    XRAY["Xray REALITY<br/>4443/tcp"]
    CLOAK["Cloak<br/>9443/tcp"]
    FW["firewall with receipts<br/>NAT44 / NAT66"]
  end

  NET(("Internet"))
  CASCADE["Cascade<br/>bridge IPv4 → exit IPv6"]
  WEB["Web panel<br/>TLS + Bearer token"]

  UI --> PROF
  PROF --> ENG
  ENG -->|"RIVET S1 / H3"| RIVET
  ENG -->|"AmneziaWG"| AWG
  ENG -->|"Xray REALITY"| XRAY
  ENG -->|"OpenVPN in Cloak"| CLOAK

  SSH -->|"bootstrap + archive"| BOOT
  BOOT --> UNITS
  UNITS --> RIVET
  UNITS --> AWG
  UNITS --> XRAY
  UNITS --> CLOAK
  USERS -->|"xio:// profiles"| PROF
  UPD --> BOOT

  RIVET --> FW
  AWG --> FW
  XRAY --> FW
  CLOAK --> FW
  FW --> NET

  ENG -.->|"free"| CASCADE
  CASCADE -.->|"IPv4 + IPv6"| NET
  WEB -->|"systemctl + admin.py"| UNITS
```

The diagram also exists as a standalone file: [docs/landing/architecture.mmd](docs/landing/architecture.mmd).

## Features

### XIO Client

- **Portable profile.** One `xio://` file for every transport of one server; import from a file or
  paste the key. Imports accept client material only: no listeners, API servers, executable
  commands, filesystem paths or direct/freedom outbounds.
- **Transport priority and fallback.** The selected profile goes first, then variants of the same
  endpoint with another protocol, then other profiles. A blocked protocol is replaced before the
  entry point changes, so the VPS address is not lost. The default first choice is Xray/REALITY, on
  iOS RIVET/S1; the order is configurable and unavailable engines are skipped.
- **Live link watchdog.** While you want the tunnel, the link is checked every 15 seconds. After two
  consecutive misses the client reconnects, retrying after 5 seconds (the first three attempts) and
  15 seconds afterwards until the server returns.
- **Honest verification.** "Interface active" alone is not a success: traffic counters and DNS
  through the tunnel must move. The site probe is an extra you can enable; with it off, the tunnel
  is confirmed by the handshake, counters and DNS.
- **Split tunnelling.** Include or exclude selected applications, and add IP/CIDR rules in either
  direction. Domain rules are not supported.
- **Subclients.** An explicitly granted account token can check quota and create or revoke only its
  own children through the server HTTPS API with a pinned certificate. A child export contains only
  that child's VPN keys and never the parent capability or SSH/root keys.
- **VPN sharing.** Android: requires root, IPv4 goes into the tunnel, DNS is redirected to
  `9.9.9.9`, IPv6 sharing is blocked. Windows: ICS-based, experimental and not verified on a live
  Windows host. Ubuntu and iOS: not available.
- **13 UI languages** with offline catalogues, dark and light themes.
- **Updates.** One check per week with a random offset; a release can be skipped. Metadata signature
  and package hash are verified before installation; Android installs through the system installer.
- **Privacy by default.** No advertising or analytics SDK, no automatic crash reporting, no
  built-in server catalogue, no endpoint geolocation. Android screens are protected with
  `FLAG_SECURE`.

### Full XIO

- **Preflight before touching the server:** OS family and version, x86_64, systemd, `/dev/net/tun`,
  busy VPN ports, subnet conflicts, existing VPN interfaces and `/etc/wireguard/xio0.conf`.
- **Install from its own bundle.** The bootstrap verifies the archive SHA-256 before unpacking; a
  truncated or substituted stream is refused instead of being unpacked as root.
- **Users and quotas.** Issue and revoke users, limit the number of active records for delegated
  admins, export profiles in batch, and keep child ownership scoped to the creator.
- **Traffic accounting.** Per-user monthly bytes and online state from server counters sampled
  every 30 seconds; RIVET, AWG and OpenVPN are counted separately.
- **Service state and secret-free logs.** Which units are active, which failed and what the server
  advertises — without keys or passwords in the output.
- **Update and rollback.** The server is updated only while the VPN is off, with saved SSH
  credentials and a matching host key; users and keys survive, and a failed update rolls back.
- **Removal that cleans up after itself.** Only XIO-owned units, rules and keys are removed; IP
  forwarding is restored and shared packages are kept.

#### Your own cascade servers 🛠️

The cascade used to be a demo only. The app now lets you configure your own pair: open the
**Cascade** screen, tap the **DNS** icon in the app bar and set the **Bridge** address (IPv4 or
domain, e.g. `81.177.142.37`) and the **Exit** address (IPv6 only, e.g. `2a0c:b641:1a0:800::2a2`).
Validation rejects schemes, ports, IPv6 in the bridge field, IPv4 in the exit field and values
like `999.1.1.1`.

The addresses are stored in the app profile, the route stations display them, and the dialog shows
the exact install command with your exit:

```bash
curl -fsSL https://raw.githubusercontent.com/rukazax/xio_vpn/main/deploy/cascade/terminal-install.sh \
  | bash -s -- --role bridge --exit-host 2a0c:b641:1a0:800::2a2
```

The "Copy command" button puts it on the clipboard. Subscription and server failover are still stubs.

## Server payload

- Five transports on one host, each with its own port and its own systemd unit.
- Managed firewall with receipts: every added rule is recorded and removed precisely; forwarding is
  scoped to the owned interfaces.
- Dual-stack: IPv4 and IPv6 listeners, NAT44 and NAT66, per-interface IPv6 subnets.
- systemd hardening: `LoadCredential` and `${CREDENTIALS_DIRECTORY}` instead of `%d` in unit files,
  `ProtectSystem=strict` where the kernel allows it, an explicit compatibility mode where it does not.
- Counters every 30 seconds; `status` returns a snapshot instead of running `wg` on every request.
- Restricted mode for IPv6-only VPS: no kernel WireGuard, no IPv4 default route, only the ports that
  can actually work.

More detail, examples and diagrams: [docs/features.md](docs/features.md).

## Five transports

![Five transports](docs/landing/protocols.en.svg)

XIO does not reinvent cryptography: each transport builds on a proven implementation, and RIVET is
our own. The transports solve different problems: speed, camouflage, and networks where UDP is
closed.

| Transport | Basis | Outer transport | Port | Use when | Android | Windows | Ubuntu | iOS |
|---|---|---|---|---|---|---|---|---|
| **AmneziaWG** | AmneziaWG 3.1 (WireGuard + obfuscation) | UDP | 51821 | fast everyday tunnel, obfuscated handshake | yes | yes | yes | - |
| **RIVET / S1** | in-house | TCP + TLS 1.3 | 8443/tcp | UDP is blocked, TLS is allowed | yes | yes* | yes* | source |
| **RIVET / H3** | in-house | QUIC / HTTP/3 + TLS 1.3 | 8443/udp | UDP works, TLS fingerprint filtering | yes | yes* | yes* | source |
| **Xray / REALITY** | Xray VLESS + REALITY | TCP | 4443/tcp | camouflage as a genuine TLS site | yes | yes* | yes* | - |
| **OpenVPN / Cloak** | OpenVPN inside Cloak | TCP + TLS obfuscation | 9443/tcp | strict networks, last resort | yes | - | - | - |

`yes` — engine present and a native run on this platform was performed; `yes*` — engine built, no
native run on this platform; `source` — engine in source, no Apple build; `-` — not available.
Android has five transports, Windows and Ubuntu four, iOS two.

The order is arranged so the protocol changes before the entry point: selected profile → same
endpoint with another transport → other profiles.

### AmneziaWG

WireGuard with an obfuscated handshake: fixed message headers are replaced, junk packets are
inserted and handshake sizes are randomised (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`). It is
still a UDP tunnel: blocking all UDP also blocks AWG. The server runs the userspace
`xio-amneziawg-go` for `xioawg0`; plain WireGuard (`xio0`) uses the kernel module and exists only in
non-restricted installs.

### RIVET

Our own development: two independent entrances to the same server, so blocking one does not kill
access.

```mermaid
flowchart LR
  C["Client"] -->|"H3: QUIC 8443/udp<br/>S1: TCP 8443/tcp"| E["RIVET entry"]
  E -->|"pin / gatewayId check<br/>user credentials"| G["RIVET gateway"]
  G --> IP["Internal address 10.79.0.N<br/>or fd79:1::N"]
  G --> NET["Internet"]
```

- Two transports (**H3** and **S1**) share one authentication, so the client switches without
  changing the profile.
- The gateway certificate is pinned (`pin`); every server has its own `gatewayId` and outer CA.
- A user gets a `secret` and an `entryToken`; the parent token is never passed to a subclient.
- Internal addressing is `10.79.0.N` with per-user traffic accounting, plus `fd79:1::/64` when the
  server advertises IPv6.

### Xray / REALITY

VLESS with REALITY: the server presents a real TLS site's parameters and the client verifies the
expected certificate/SNI pair. On the wire it looks like ordinary HTTPS. On the tested pair
"client 0.23.x + gateway Xray 26.7.28" REALITY does not connect; see
[Limitations](#limitations-what-is-not-verified).

### OpenVPN / Cloak

OpenVPN wrapped in Cloak's TLS obfuscation. It exists for networks where only TCP/443-like traffic
is allowed and is the client's last resort. Only Android declares the Cloak engine.

### Server-side transports

WireGuard, Shadowsocks and IKEv2 are installed on the server but not offered by the XIO client.
They exist for compatibility with other clients and for restricted deployments.

| Port | Protocol | Service | Notes |
|---|---|---|---|
| 8443/tcp + 8443/udp | TCP / QUIC | RIVET S1 and H3 | TLS 1.3, pinned gateway certificate |
| 4443/tcp | TCP | Xray / REALITY | VLESS, masquerades as a real site |
| 9443/tcp | TCP | Cloak | OpenVPN TCP behind TLS obfuscation |
| 1194/udp | UDP | OpenVPN UDP | direct, no Cloak |
| 1195/tcp | TCP | OpenVPN TCP | loopback only, exposed through Cloak |
| 51821/udp | UDP | AmneziaWG | obfuscated WireGuard |
| 51820/udp | UDP | WireGuard | non-restricted installs only |
| 8388/tcp + 8388/udp | TCP/UDP | Shadowsocks | server-side only |
| 500/udp, 4500/udp | UDP | IKEv2 / IPsec | server-side only |
| 9444/tcp | TCP | Account API | only when an account token is granted |

Deep dives: [protocol notes](docs/en/protocols.md) · [RIVET library](docs/protocols/README.md) ·
[RIVET implementation 0.2 (RU)](RIVET-IMPLEMENTATION-0.2.ru.md).

## IPv4 and IPv6

![IPv4 and IPv6](docs/images/xio-dualstack-en.svg)

The outer transport and the inner address are independent:

- An endpoint may be an IPv4 address, an IPv6 address, or a domain with A and/or AAAA records.
- Xray and Cloak try both address families. RIVET tries them sequentially, because concurrent
  authorisation of one identity can replace a peer.
- RIVET/S1, RIVET/H3, AmneziaWG and OpenVPN carry IPv4 and IPv6 inside the tunnel. IPv6 addresses
  are issued only by a server that explicitly advertises support.
- Managed addressing, forwarding and NAT66 require real provider routing. Only owned changes are
  made, each with a receipt and a precise rollback.
- DNS comes from the profile and goes through the tunnel.
- **XIO does not provide DNS64, NAT64 or CLAT.** IPv4 literals and IPv4 packets are not translated
  inside an IPv6-only network; such a host needs an IPv4 egress or provider-side NAT64.
- IPv6 extension headers, fragments and jumbograms are not supported. TCP, UDP and limited ICMPv6 are.

| Transport | IPv4 subnet | IPv6 subnet |
|---|---|---|
| WireGuard (non-restricted) | `10.77.0.0/24` | `fd77:1::/64` |
| AmneziaWG | `10.78.0.0/24` | `fd78:1::/64` |
| RIVET | `10.79.0.0/24` | `fd79:1::/64` |
| OpenVPN UDP | `10.80.0.0/24` | `fd80:0::/64` |
| OpenVPN TCP | `10.81.0.0/24` | `fd80:1::/64` |
| IKEv2 / IPsec | `10.82.0.0/24` | - |

### IPv6-only VPS

`restrictedNetwork` mode is for a server that has no IPv4 default route:

- no kernel WireGuard and no `xio0`; AmneziaWG runs in userspace;
- only transports that can work are installed: AWG, RIVET, Xray, Cloak, OpenVPN TCP;
- the firewall opens `4443/tcp`, `9443/tcp`, `8443`, `51821/udp` — not the IPv4-only set;
- the preflight records `outboundByFamily: {ipv6: eth0}` and reports `ipv4DefaultRoute: false`
  instead of pretending the host is dual-stack.

Verified on a VPS with global IPv6 `2a0c:b641:1a0:800::2a2`: the client receives `fd79:1::fe/128`,
`ping6` and `wget -6` pass through the tunnel, and the answer comes from the VPS global address
(NAT66). The outer IPv6 entry `[2a0c:b641:1a0:800::2a2]:18443` connected in 129–159 ms.

## Cascade: two servers, IPv4 → IPv6

The cascade is free: no subscription, no account. The device reaches **bridge** over AmneziaWG
(IPv4), the bridge keeps an **SSH TUN** to **exit**, and the exit serves traffic to the internet
over IPv4 and IPv6. This exact scheme was deployed and verified on 17 Nov 2026 on the live pair
`81.177.142.37` (RU) → `103.102.135.124` (FR).

![Cascade route](docs/landing/cascade-route.en.svg)

```mermaid
flowchart LR
  A[Phone<br/>AmneziaWG, IPv4] -->|UDP 51821| B[Bridge<br/>IPv4]
  B -->|SSH TUN<br/>10.250.0.1 ⇄ 10.250.0.2| C[Exit<br/>IPv4 + IPv6]
  C --> D((Internet<br/>IPv4 / IPv6))
```

**What the app shows in 0.24.8.** The main-screen card and the Cascade screen report the same
state:

- three stations — 🇷🇺 device → 🇷🇺 bridge → 🇫🇷 exit — with addresses and country flags;
- the real egress: `103.102.135.124 FR` for IPv4 plus the exit's global IPv6;
- "Cascade active" only while the tunnel is actually up, not just because addresses are saved;
- "Check cascade": with a saved SSH server it really probes the bridge; without one it honestly
  asks `api.ipify.org` for the actual egress and stores the address and country. No demo timers,
  no fake latency.

Real POCO X6 captures, not mockups:

| Main screen with cascade flags | IPv4 egress | IPv6 egress |
|---|---|---|
| ![Main: 🇷🇺 device → 🇷🇺 bridge → 🇫🇷 exit, egress 103.102.135.124 FR](docs/screenshots/android-cascade-flags-20261117.png) | ![api.ipify.org returns 103.102.135.124](docs/screenshots/android-cascade-egress-ipv4-20261117.png) | ![api6.ipify.org returns 2a0c:b641:1a0:800::2a2](docs/screenshots/android-cascade-egress-ipv6-20261117.png) |

**Installing on live servers — `deploy/cascade/native/`.** Native scripts and systemd units,
not a Docker container; they are idempotent, and `systemctl restart` recreates the rules without
duplicating them.

1. **Exit** (`103.102.135.124`): put `xio-cascade-exit-{up,down}.sh` into `/usr/local/sbin/` and
   `xio-cascade-exit.service` into `/etc/systemd/system/`, then
   `systemctl enable --now xio-cascade-exit`. The unit brings up `tun0` `10.250.0.2/30` and
   `fd78:2::2/64`, forwarding and NAT44/NAT66.
2. **Bridge** (`81.177.142.37`): install its scripts and unit the same way, write
   `XIO_CASCADE_EXIT_HOST=103.102.135.124` to `/etc/xio-cascade/bridge.env`, then
   `systemctl enable --now xio-cascade-bridge`. The unit keeps `ssh -N -w 0:0` to the exit and
   restarts on failure.
3. **SSH trust** once: `PermitTunnel yes` on the exit; the bridge key `/root/.ssh/xio_cascade`
   added to the exit's `authorized_keys`.

Measured on that pair: `ping 10.250.0.1` from the exit — 50.8 ms; 20 MiB through `tun0` —
2.309 s (**69.3 Mbit/s**) with BBR on the bridge, `tcp_mtu_probing=1` and 16 MiB buffers;
without BBR the same pair collapsed to 1.5 Mbit/s at ≈8 % loss. Commands and numbers:
[docs/CASCADE-ANDROID-RU-FR-20261117.md](docs/CASCADE-ANDROID-RU-FR-20261117.md).

| What | Where |
|---|---|
| Verified native scripts and units | `deploy/cascade/native/` |
| Container installer for bridge/exit/both (earlier path) | `deploy/cascade/`, `deploy/cascade/terminal-install.sh` |
| Health check | `deploy/cascade/cascade-healthcheck.sh` → `/var/lib/xio-cascade/health.json` |
| Whitelists on the bridge | `deploy/cascade/whitelist-update.sh`, weekly timer |
| Server web UI (TLS + token) | `server/webui/` |
| Full description and diagram | [docs/cascade/README.md](docs/cascade/README.md) |

**Your own cascade servers.** On the Cascade screen the **DNS** icon opens a dialog:

| Field | What to enter | Validation |
|---|---|---|
| **Bridge** | IPv4 or domain, e.g. `81.177.142.37` | rejects schemes, ports, IPv6 and "999.1.1.1" |
| **Exit** | IPv6 literal, e.g. `2a0c:b641:1a0:800::2a2` (brackets allowed) | rejects IPv4, DNS names and garbage |

The addresses are stored in the profile, the stations show them, and the dialog offers a ready
install command. In the verified pair the exit is set by IPv4 in `bridge.env` because the SSH TUN
runs over IPv4; the app dialog currently accepts only an IPv6 literal in the Exit field. That is
a UI limitation, not a server-side one.

**Honest cascade limits:**

- there is no single button that installs the cascade on both servers; the bridge and the exit
  are separate steps, although both script sets are in the repository;
- updating or reinstalling the APK breaks the saved native receipt: a clean install, profile
  import and connection work, but after a reinstall the app may report
  "saved plan could not be reconciled";
- the SSH TUN is TCP-over-TCP: it survives on BBR, and BBR is enabled on the bridge but not on
  the exit (kernel without `tcp_bbr`); one path, no backup;
- WireGuard between the servers did not come up for data: the handshake succeeds but transport
  packets are lost, which is why the SSH TUN was chosen;
- the mobile profile uses `9.9.9.9` for DNS and the queries go through the cascade;
- Yandex Browser on the test phone renders a blank page while the tunnel works; Chrome works.
  This is browser behaviour, not the cascade.

## Install a server

![Three ways to install a server](docs/landing/install-flow.en.svg)

**A clean VPS is required:** x86_64, Debian 12/13, Ubuntu 22.04/24.04/26.04, or RHEL/Alma/Rocky
9/10, systemd, `/dev/net/tun`, no other VPN on the host.

### 1. From the app (recommended)

1. Open **Full XIO** → "+" → server setup.
2. Enter the address and SSH credentials (key or password).
3. The preflight checks OS, architecture, systemd, TUN, ports and subnets.
4. Install: the app uploads its own bundle, verifies the digest, installs the services and reports
   the unit state.
5. Create users and export their `xio://` profiles.

### 2. One command in a terminal

The bootstrap reads the archive from stdin. Take both names from the
[Releases](https://github.com/rukazax/xio_vpn/releases) page — a release candidate carries a `-rcN`
suffix in the tag while its asset keeps the plain version number, so they are separate variables:

```bash
TAG=0.24.1-rc13                  # tag on the release page, without the leading "v"
FILE=xio-server-0.24.1.tar.gz    # asset name on that release
curl -fsSLo xio-server.tar.gz \
  "https://github.com/rukazax/xio_vpn/releases/download/v${TAG}/${FILE}"
curl -fsSLo xio-bootstrap.sh \
  https://raw.githubusercontent.com/rukazax/xio_vpn/main/server/managed/bootstrap.sh
sudo XIO_EXPECTED_ARCHIVE_SHA256="<sha256 from SHA256SUMS>" \
  bash xio-bootstrap.sh < xio-server.tar.gz
```

If `v0.24.1` is already published, use it as `TAG` — the stable tag has no `-rc` suffix.

Without `XIO_EXPECTED_ARCHIVE_SHA256` the bootstrap still refuses a broken archive, but the digest
pin is what makes a substituted stream stop before it is unpacked as root. Take the hash from
`SHA256SUMS-<version>.txt` on the release page.

> **Server package versions matter.** 0.23.1 shipped a payload that failed the firewall step
> (`iptables: Can't use -i with POSTROUTING`) and broke `status` on IPv6-only hosts. 0.24.0 fixed
> that but its packager left `readiness.py` and `xio-ready.service` out of the tarball, so an
> install on a clean host ended with exit code 1 on the last step. Both are fixed in 0.24.1
> (`RECIPE` 26). For a new server take **0.24.1 or newer**.

### 3. The web panel

```bash
sudo ./install-webui.sh                 # https://127.0.0.1:10443
sudo ./install-webui.sh 0.0.0.0:10443   # all interfaces, behind a reverse proxy only
```

The script prints the URL with a token, the token itself and the certificate SHA-256 fingerprint.
Services, users and the cascade are managed from one page; the panel speaks TLS only, uses a
Bearer token plus a `SameSite=Strict` cookie and requires a CSRF header for POST. Details:
[server/webui/README.md](server/webui/README.md).

### What ends up on the server

| Path | Contents |
|---|---|
| `/usr/local/lib/xio-managed` | server code: `admin.py`, `stack.py`, `network_stack.py`, `dualstack.py`, binaries |
| `/etc/xio-managed/deployment.json` | deployment state: host, users, keys, counters, receipts — without per-client configs |
| `/etc/xio-rivet` | RIVET public state and installer receipt |
| `/usr/local/lib/xio-rivet` | RIVET binary and setup script |
| `/var/lib/xio-stack` | stack counters and runtime state |

Units: `xio-managed-awg`, `xio-managed-stats.timer`, `xio-rivet-entry`, `xio-rivet-gateway`,
`xio-stack`, `xio-cloak`, `xio-openvpn-udp`, `xio-openvpn-tcp`, `xio-ikev2`, `xio-client-api`,
`xio-ready`.

Administration is JSON on stdin:

```sh
printf '%s\n' '{"action":"status","serverId":"<id>"}' \
  | python3 /usr/local/lib/xio-managed/admin.py
```

| Action | What it does |
|---|---|
| `init` | first installation; `host` and `restrictedNetwork` are required |
| `inspect` | public server description and phase |
| `status` | services, counters, users, monthly traffic |
| `add` | create a user and return per-transport configs |
| `revoke` | revoke a user and its children |
| `remove` | remove only XIO-owned units, rules, keys and packages |
| `client-grant` | issue a scoped account token for subclients |

## Clients by platform

`XIO-<App>-<version>-<OS>-<arch>.<ext>`. `App` is `Client` or `Full`, `OS` is `android`, `windows`
or `ubuntu`, architecture is `arm64-v8a`, `armeabi-v7a`, `x86_64`, `universal`, `amd64` or `x64`.

Everything is on the [Releases](https://github.com/rukazax/xio_vpn/releases) page, including
`SHA256SUMS` files. Verify with `sha256sum -c SHA256SUMS-<version>.txt` or
`Get-FileHash <file> -Algorithm SHA256`.

### Android — Full or Client?

| | **XIO Full** (`app.xio.xio`) | **XIO Client** (`app.xio.client`) |
|---|---|---|
| Connect to an existing server | yes | yes |
| Own server over SSH | yes | no |
| Users, quotas, revocation | yes | no (subclients only, if granted) |
| VPN sharing | yes | no |
| Five transports | yes | yes |
| Package size | ~58 MB | ~57 MB |

Android 8+; ARM64 is the usual choice, ARM32 for old devices, x86_64 for emulators, `universal` if
you do not want to think about it. Open the APK, allow installation from this source, and the
update installs over the previous version keeping profiles.

On MIUI/HyperOS `adb install` may answer `INSTALL_FAILED_USER_RESTRICTED`. The working path:

```bash
APK=XIO-Full-<version>-android-arm64-v8a.apk
adb push "$APK" /data/local/tmp/xio.apk
adb shell pm install -r -g /data/local/tmp/xio.apk
```

Android 0.24.1 is `0.24.1+5018`, signed with the same certificate (SHA-256 `e4e81b12…c9671`; the
alias of the historical signature is kept in the keystore), so it updates over 0.23.x/0.24.x
without uninstalling. The newest APKs on the Releases page are 0.24.0 —
the 0.24.1 Android set is being prepared, and its notes are in
[docs/release-notes-0.24.1-mobile.md](docs/release-notes-0.24.1-mobile.md).

### Windows 11 x64

Fully unpack the ZIP and run `XIO.exe`. The helper `libexec\xio-tunnel.exe` starts elevated: it
needs that to create the network interface. Wintun is included with its licence. Four transports
(no Cloak). The build is not signed with a publisher certificate, so SmartScreen warns — that is
expected.

- Full XIO for Windows: in the 0.24.0 release.
- XIO Client for Windows: published in 0.23.1; 0.24.0 did not include it.

### Ubuntu 22.04+

```bash
sudo apt install ./XIO-*-ubuntu-amd64.deb
```

The package name drifted between releases (`XIO-Full-…-ubuntu-amd64.deb` in 0.24.0,
`XIO-…-ubuntu-amd64.deb` in 0.24.1), hence the wildcard — or unpack the `.tar.gz`.

The GUI runs as your user; the network helper asks for system authorisation through polkit.
`systemd-resolved` is required: without it the connect is rejected with
`systemd-resolved could not configure VPN DNS`. Four transports.

> The 0.24.0 packages are built, but the GUI was not re-verified live (in 0.23.0 the window never
> appeared: the process lived, the Impeller/EGL surface did not come up). The tunnel works through
> `libexec/xio-tunnel`.

### iOS

There is no IPA. The source supports RIVET/H3 and S1 and needs a Mac, Xcode, an Apple Developer team
and NetworkExtension entitlements. See [build from source](docs/en/build.md).

### Screenshots

<p><img src="docs/images/2026-10-26-full-home.png" width="220" alt="Full XIO home"> <img src="docs/images/2026-10-26-win-windows-home.png" width="220" alt="XIO Client for Windows"> <img src="docs/images/client-0.22.4-dark.png" width="220" alt="XIO Client, dark theme"></p>

Fresh Android frames produced by the golden render
(`app/test/screenshots/capture_screens_test.dart`, command in
[docs/screenshots/README.md](docs/screenshots/README.md)):

| Home, disconnected | "Connection settings" tab |
|---|---|
| ![Home: disconnected, server chosen](docs/screenshots/main-idle.png) | ![Connection settings: key, own server, "Cascade VPN on your own VPS", users](docs/screenshots/connection-tab.png) |

| "DNS resolver": presets and custom addresses | "Telegram proxy (MTProto)": steps and the saved link |
|---|---|
| ![DNS resolver: AdGuard, Quad9, Cloudflare, Google Public DNS and "Custom"](docs/screenshots/settings-dns.png) | ![MTProto proxy: instruction, tg://proxy link and the "Proxy configured" status](docs/screenshots/settings-mtproto.png) |

| "Routing": IP/site modes and the domains field |
|---|
| <img src="docs/screenshots/routing-domains.png" width="260" alt="Routing: mode «Only the selected IPs/sites through the VPN», the IP list 203.0.113.5 and 192.168.0.0/16, and the «Domains and sites» field with youtube.com and *.example.com"> |

Android screens on the phone stay black in a system screenshot: the app sets `FLAG_SECURE`. That is
protection, not a bug — the Android images in the docs come from Flutter widget tests. The list of
frames we still need, with exact `adb` commands and a status table, is in
[docs/screenshots/README.md](docs/screenshots/README.md).

## Split tunnelling

Include or exclude selected applications, and add IP/CIDR rules in either direction. Domain rules
are not supported: routing by name needs its own resolver, and XIO does not have one yet.

Excluded traffic goes directly — unless Android lockdown forbids it, in which case the system rule
wins over the setting. In a cascade the rules live on the bridge (`xio_whitelist4` nft set), are
refreshed weekly and replaced atomically.

## Security

- **Profile secrets are encrypted at rest.** Android Keystore with backups disabled, Windows DPAPI,
  Ubuntu AES-GCM with a local key and file permissions, iOS Keychain.
- **The client never receives server keys.** SSH, root and admin credentials stay in the full
  application; subclients get only their own VPN keys.
- **SSH host keys are pinned.** A changed key stops maintenance until the owner confirms it.
- **The bootstrap verifies the archive digest** before unpacking; a substituted stream is refused.
- **Per-client configs are not written into `deployment.json`.** A replay returns
  `configsUnavailable` instead of handing out secrets twice.
- **Secrets are compared in constant time** in `rivet user add` and token checks.
- **Unit files use a credentials directory**, not `%d`, so secrets are not expanded into the command
  line.
- **Sandbox is explicit.** `ProtectSystem=strict` is used where a read-only bind mount works;
  otherwise XIO records `sandboxMode: compat` and drops only that directive, keeping `PrivateTmp`,
  `NoNewPrivileges` and capability bounding.
- **Imports are sanitised.** A profile cannot add listeners, API servers, commands, filesystem paths
  or direct/freedom outbounds.
- **No telemetry.** No advertising or analytics SDK, no automatic crash reporting, no server
  catalogue.

## How we test

The rule is simple: **only an observed result on real hardware counts as evidence, not a successful
build.**

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
| Artifacts | APK signature, `package`/`versionCode`, ABI and 16 KB alignment | does not prove a connection |
| Stand | the server is installed from the shipped bundle and a client connects over a real network | does not prove phone behaviour |
| Device | install on a physical Android device / run on Windows | does not prove the route |
| Independent check | HTTPS inside the tunnel, `ping` to the tunnel gateway, server counters and `endpoint` | - |

`FAIL`, `BLOCKED` and `NOT_EXECUTED` are written as such and never replaced with "works". Details:
[compatibility 0.24.0](docs/compatibility/0.24.0.en.md) ·
[physical Android run](docs/verification/android-physical-2026-10-21.en.md).

## FAQ

**Is XIO a subscription VPN?** No. It is software you run on your own VPS. The cascade is free
too: no subscription, no billing, no third-party account.

**Do I need root?** Not for the VPN itself. Root is needed for VPN sharing on Android.

**Which transport will it pick?** Xray/REALITY first by default, then the alternatives of the same
server, then other profiles. You can reorder them; a blocked protocol is replaced before the entry
point changes.

**It says "tunnel active" but nothing loads.** Check counters and DNS on the connection screen —
they are the real proof. If they do not move, the server side is the usual suspect: NAT, firewall,
or DNS. "Interface active" without traffic is not a success by design.

**Can I run it next to another VPN?** No. The `/1` routes conflict; disable the other tunnel.

**Where do I get iOS?** Nowhere yet: there is source, not an IPA. It needs a Mac, Xcode and Apple
signing.

**The server install failed at the last step.** That is the known 0.24.0 packager defect
(`readiness.py` and `xio-ready.service` missing). Take 0.24.1 or newer.

**Does it guarantee bypassing blocks?** No. There are no field measurements with Russian carriers
and no independent audit of RIVET. Reaching the entry point and camouflaging the transport are two
different jobs.

## Limitations (what is not verified)

- **Xray/REALITY does not connect** on "client 0.23.x + Xray 26.7.28 gateway": the REALITY
  implementation in the client core is incompatible. AWG and RIVET work.
- **AWG on Android in this branch (`main`):** `tun.CreateUnmonitoredTUNFromFD` can hand the TUN
  descriptor to a Go finalizer, which later closes a number that already belongs to something else;
  an AWG activation that failed earlier can then kill an unrelated socket (`i/o timeout`,
  `accept4: bad file descriptor`). The fix — duplicating the descriptor first — is in the
  `release-0.24.0` branch (`c2b3338`), `main` does not have it yet.
- **Windows 0.24.0:** the helper is rebuilt with the WFP firewall fix (rules by user SID and App ID
  instead of `netsh`), analyze, tests and packaging pass. A live GUI connection on 0.24.0 was not
  re-run; the last live run was the 0.22.5 helper with the 0.23.0 application.
- **Ubuntu GUI:** 0.24.0 packages are built, the GUI was not re-verified live. The tunnel works
  through `libexec/xio-tunnel` and needs `systemd-resolved`.
- **A full tunnel on Linux cuts off the local network:** while the tunnel is up the machine stops
  answering SSH from the LAN, because all unmarked IPv4 goes into the tunnel.
- **Cascade:** verified on the live pair `81.177.142.37` → `103.102.135.124` (SSH TUN, IPv4 +
  IPv6 egress, 69.3 Mbit/s with BBR). Limits: no one-button install on both servers, TCP-over-TCP
  without a backup path, the native receipt breaks when the APK is reinstalled; see the Cascade
  section for details.
- **The web panel** is deployed and answers on a live server (`https://79e.ru/xio/`, health 1.1.0);
  the terminal bootstrap was not re-run in this pass.
- **Windows ICS sharing** was not validated on a live host.
- **IPv6 must be routed by the provider.** XIO configures addressing, forwarding and NAT66 on its own
  interfaces, but cannot make an upstream announce or route a prefix. DNS64/NAT64 are not provided.
- **iOS** is not built: no Mac/Xcode/iPhone, no IPA.
- **Full protocol parity is not achieved:** Android 5 transports, Windows/Ubuntu 4, iOS 2.
- **Alongside another VPN** XIO does not work: the `/1` routes conflict.
- The Windows application is not signed with a publisher certificate, so SmartScreen warns.

## Clone and build from Git

A plain clone is enough. The modified AWG sources are tracked files, not submodules and not Git
LFS: `vendor/amneziawg-go` (upstream `amnezia-vpn/amneziawg-go` v3.1.20260814 plus the XIO
activation API documented in `vendor/amneziawg-go/XIO-CHANGES.md`) and `vendor/amneziawg`
(Android bridge with the prebuilt `jniLibs`). `protocol/rivet/go.mod` replaces the module with
`../../vendor/amneziawg-go`, so `go build ./...` works straight after cloning.

```sh
git clone --recurse-submodules https://github.com/rukazax/xio_vpn.git
cd xio_vpn
cd app && flutter pub get && flutter analyze   # app/pubspec.yaml
cd ../protocol/rivet && go build ./...         # Go 1.27.x
```

`--recurse-submodules` is harmless and future-proof, but does nothing here: there is no
`.gitmodules`, and `git submodule update --init --recursive` is a no-op as well. Only build
artifacts stay out of the tree: `tools/build-rivet.py` produces `vendor-server/*` and the AAR,
and `python3 tools/package-server.py --check` verifies them against
`vendor-metadata/rivet-build.json`.

## Documentation

- [Features in detail](docs/features.md) · [Возможности (RU)](docs/features.ru.md)
- [Compatibility and status 0.24.0](docs/compatibility/0.24.0.en.md)
- [Guide](docs/en/guide.md) · [Downloads](docs/en/downloads.md) · [FAQ](docs/en/faq.md) · [Build](docs/en/build.md)
- [Protocols](docs/en/protocols.md) · [RIVET library](docs/protocols/README.md) · [Dual-stack notes](docs/dualstack/0.22.3.en.md)
- [Cascade](docs/cascade/README.md) · [Web panel](server/webui/README.md) · [Client and subclients](client/README.en.md)
- [Release notes 0.24.0](docs/release-notes-0.24.0.md) · [0.24.1 mobile](docs/release-notes-0.24.1-mobile.md) · [Changelog](CHANGELOG.md)
- [Screenshots to take](docs/screenshots/README.md) · [Diagrams](docs/landing/architecture.mmd) · [Third-party notices](THIRD-PARTY-NOTICES.md)

## License

Original code is GPL-3.0-only. Third-party components keep their own licences:
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Security reports:
[SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).
