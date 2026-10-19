# XIO 0.22 protocols

[Русский](../ru/protocols.md) · [Guide](guide.md)

| Connection | Android | Ubuntu / Windows | Purpose and limits |
|---|---|---|---|
| Xray: VLESS, VMess, Trojan | Yes | Yes | TLS/REALITY with supported XHTTP, TCP, WebSocket, gRPC and HTTP Upgrade settings matching the server |
| RIVET/S1 | Yes | Yes | Experimental XIO TLS/WebSocket transport with a pinned server certificate |
| RIVET/H3 | Yes | Yes | Experimental HTTP/3/QUIC transport; requires reachable UDP |
| AmneziaWG | Yes | Yes | AWG transport obfuscation, including validated 3.1 fields; cannot restore blocked UDP or a blocked IP |
| Cloak | Yes | No | Cloak with internal OpenVPN; no standalone OpenVPN connection |
| RIVET for iOS | Source project | — | S1/H3 implemented in source; no signed IPA or Apple-device validation |

Plain WireGuard, OpenVPN, IKEv2, Shadowsocks and Tailscale are removed from supported client connections. Their old standalone profiles cannot connect. Mixed user bundles retain supported configurations. Cloak's internal OpenVPN and shared AWG infrastructure remain. This product choice does not prove that removed protocols fail everywhere.

Automatic selection uses available configurations belonging to the same user. Default order: Xray → RIVET/S1 → Cloak → AWG → RIVET/H3; unavailable platform engines are skipped. A preferred protocol can change the order. An unsuccessful attempt is disconnected before fallback. An imported single profile does not acquire imaginary backup configurations.

RIVET uses established cryptographic libraries. Its wire format is unchanged in 0.22. VLESS Encryption support uses Xray cryptography, not a new XIO cipher. RIVET has no independent security audit or proven browser indistinguishability. Read the [network limitations article](../blog/2026-10-19-restricted-networks.md#english) and [video review](../research/2026-10-19-video-protocols.en.md).

![Reachable entry and transport](../images/allowlist-entry-en.svg)

TLS still exposes the entry IP. A strict allowlist needs a reachable ingress and a working path to the exit. XIO does not automatically supply a reachable CDN or turn an unrelated website into a relay.
