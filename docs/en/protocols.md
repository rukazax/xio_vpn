# XIO protocols

[Русский](../ru/protocols.md) · [Home](../../README.md)

| Engine | Android | Ubuntu / Windows | iOS |
|---|---|---|---|
| WireGuard | Yes | Yes | No |
| AmneziaWG 3.1 | Yes | Yes | No |
| Xray / REALITY | Yes | Yes | No |
| Shadowsocks | Yes | Yes | No |
| OpenVPN | Yes | No | No |
| OpenVPN / Cloak | Yes | No | No |
| IKEv2 / IPsec | Yes | No | No |
| Tailscale / Headscale | Yes | Yes | No |
| RIVET / H3 | Yes | Yes | Source integration |
| RIVET / S1 | Yes | Yes | Source integration |

Yes means an integrated engine, not guaranteed connectivity in every network. See the main page for Windows and iOS verification limits. Tailscale/Headscale integrates a mesh client and control server; it is not a cryptographic protocol invented by XIO.

## RIVET/H3

An experimental IP-packet transport: inner QUIC/TLS 1.3 passes through outer HTTP/3 CONNECT-UDP (MASQUE). The entry checks a token; the gateway uses a pin and device HMAC. Inner TLS uses X25519MLKEM768 from the Go standard library. It uses established libraries. The project defines transport and management behaviour, rather than independently audited new cryptography. Networks can block UDP, and using HTTP/3 does not by itself conceal a VPN.

## RIVET/S1

An experimental fallback transport: inner TLS 1.3 is carried by WebSocket over outer TLS/TCP (WSS). The client checks the outer server certificate and gateway pin and authenticates with its credentials. It is intended for paths where UDP does not work. Ordered TCP delivery can increase latency under packet loss. TLS alone does not establish a browser-like traffic fingerprint.

## Implementation and evidence

[RIVET sources](../../protocol/rivet/) · [Original architecture and threat model, Russian](../../research/RIVET-1-ARCHITECTURE.ru.md) · [0.19 verification, Russian](../../verification/VERIFICATION-0.19.0.ru.md).

The architecture document includes design proposals and hypotheses. Code and version-specific reports define implemented behaviour. There is no claim of independent auditing, resistance to every blocking method or absolute anonymity. The desktop version does not yet have a full system kill switch between attempts; IPv6 is blocked during a connection.
