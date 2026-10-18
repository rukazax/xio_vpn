# XIO: an open client for your own VPN server and experimental RIVET transports

A project-authored introduction, prepared with AI assistance. This is not an independent review. Project snapshot: 18 October 2026.

## Your server, one interface

XIO stands for X in 1 out. We are building a client that combines your own VPS, imported connection profiles, user management and connection diagnostics. The idea is straightforward: manage your connections in one application and distinguish integrated features from verified results.

[Project source](https://github.com/rukazax/xio_vpn) · [Builds and instructions](https://github.com/rukazax/xio_vpn/releases/tag/v0.20.0).

![XIO overview](https://raw.githubusercontent.com/rukazax/xio_vpn/main/docs/images/overview.svg)

## What the client does

XIO can install components on your VPS over SSH, import supported configurations, identify the engine automatically, create users and export access profiles. You can choose a preferred protocol, connection timeout and HTTPS test website. When an attempt fails, the connection manager tries the next available profile.

Android includes split tunnelling, system theme support, icon selection and 13 languages. The shared interface uses Flutter. Integrated engines include WireGuard, AmneziaWG, Xray, Shadowsocks, OpenVPN, Cloak, IKEv2, Tailscale/Headscale and RIVET, with different platform availability. Integrating these third-party projects does not make them our cryptographic inventions.

## What RIVET adds

RIVET/H3 and RIVET/S1 are experimental carriers in one family. H3 carries an inner QUIC session through HTTP/3 CONNECT-UDP. S1 carries an inner TLS session through binary WebSocket over HTTPS/TCP. They provide two delivery paths with common authentication logic.

![RIVET layers](https://raw.githubusercontent.com/rukazax/xio_vpn/main/docs/protocols/images/architecture-en.png)

Entry checks a separate admission token. The inner gateway is authenticated by an SPKI pin; the device proves knowledge of its secret using HMAC bound to a nonce, TLS exporter and exact session parameters. Inner TLS requires TLS 1.3 and X25519MLKEM768 hybrid key agreement. Server authentication remains classical ECDSA P-256. We use existing cryptographic libraries rather than presenting this composition as independently audited new cryptography.

## What the measurements show

In the saved experiment, each carrier completed ten CLI probes including handshake, pin verification and a DNS response through the gateway. Median complete-probe duration was 759 ms for H3 and 919 ms for S1. This is a small single-VPS sample, not download throughput or a cross-country comparison.

![Probe observations](https://raw.githubusercontent.com/rukazax/xio_vpn/main/docs/protocols/images/probe-en.png)

Chart inputs and generation code are published. A separate fresh local check passed 15 core Test functions with the Go race detector and seed cases for two fuzz functions. It does not establish a new extended fuzz campaign or VPS test cycle.

## Current boundaries

RIVET currently carries IPv4 user traffic; it is not a complete dual-stack tunnel. There is no independent audit. Browser indistinguishability, absolute anonymity and operation in every network are not established. Gateway is trusted, and OS-account separation on one VPS does not protect against root or the hypervisor. Desktop runtime still lacks a complete system kill switch between attempts.

Android builds are available for ARM64, ARMv7 and x86_64. Ubuntu x64 has DEB and portable archives. Windows is a preview: the UI was tested in Wine, while native networking needs separate validation. iOS currently provides an Xcode source project without a signed IPA. A physical Honor Magic V3 has not been separately tested.

## Source and documentation

Original code uses GPL-3.0-only; third-party components retain their licences. The complete source release includes dependencies and the exact shipped Android runtime sources. The GitHub branch contains original code and documentation, excluding large vendor snapshots and prebuilt libraries.

[RIVET technical library: diagrams, wire formats and evidence](https://github.com/rukazax/xio_vpn/tree/main/docs/protocols).

[Exact engine and platform matrix](https://github.com/rukazax/xio_vpn/blob/main/docs/en/protocols.md).

[Feedback and bug reports](https://github.com/rukazax/xio_vpn/issues). Never attach passwords, private keys or access profiles. Follow SECURITY.md for vulnerabilities.

The most useful contributions are reproducible bug reports, physical-device testing, source review and documentation improvements. Opening the project invites technical scrutiny; it is not a claim that every platform is production-ready.
