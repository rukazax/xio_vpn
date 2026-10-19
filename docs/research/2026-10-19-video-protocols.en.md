# Protocols discussed by AlumPC: review and XIO integration decisions

2026-10-19 · [Русский](2026-10-19-video-protocols.ru.md) · [XIO 0.22 changes](../blog/2026-10-19-restricted-networks.md#english)

The questions came from [AlumPC's protocol overview](https://youtu.be/ZuMZRs8ofh4), published 2026-10-18. We read its complete auto-generated Russian transcript and description, then checked technical claims against project sources. Auto-captions distort technical names. Visual demonstrations and the paid follow-up were not treated as evidence.

## Primary sources and integration decisions

| Project | Useful mechanism | Decision for this release |
|---|---|---|
| [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) | Configurable UDP packet representation and obfuscation | Keep as a candidate; it cannot overcome a blanket UDP block |
| [Hysteria 2 protocol](https://v2.hysteria.network/docs/developers/Protocol/) | QUIC authentication, HTTP/3 handling, bounded fragmentation/reassembly | Relevant to RIVET threat modelling; no Hysteria interoperability claim |
| [Hysteria configuration](https://v2.hysteria.network/docs/advanced/Full-Server-Config/) | Salamander and experimental Gecko | Not blindly enabled: obfuscation removes normal HTTP/3 compatibility and still needs UDP |
| [TUIC v5 specification](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md) | Multiplexing and stream/datagram relaying | A maintained implementation must be selected; TUIC does not mandate one browser-like stack |
| [Mieru](https://github.com/enfein/mieru) | Its own secure transport and traffic shaping | No basis for declaring it broken throughout Russia; no new engine shipped |
| [AnyTLS specification](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md) | Authentication and multiplexed/padded sessions over established TLS | Do not infer arbitrary TLS ClientHello mutation from application padding; integration needs its own engine/tests |
| [NaïveProxy](https://github.com/klzgrad/naiveproxy) | Chromium networking, CONNECT and early-exchange padding | A separate integration candidate, not part of this release |
| [uTLS](https://github.com/refraction-networking/utls) | TLS ClientHello fingerprint control | Used through upstream Xray; not an entire browser or IP routing substitute |
| [REALITY](https://github.com/XTLS/REALITY) | Client authentication and unauthenticated-connection handling | Retained in Xray; does not obtain another site's private key |
| [Pinned VLESS Encryption code](https://github.com/amnezia-vpn/amnezia-xray-core/blob/v1.260728.0/infra/conf/vless.go) | Additional protection behind TLS-terminating intermediaries | Checked key/config import and actual local exchanges; outer TLS/REALITY required |
| [XHTTP](https://xtls.github.io/en/config/transports/xhttp.html) | Different upload/download patterns and connection controls | Four modes tested; two reproduced races fixed with a public patch |

## Claims that need qualification

An allowlist can use names, SNI, IPs, prefixes or combinations. A result from one subscriber is not a country-wide guarantee. Nested TLS does not expose the inner ClientHello in plaintext to an ordinary ISP; observable sizes and timing can still support traffic classification.

REALITY's fallback and authentication are not theft of a certificate's private key and do not erase destination IP checks. AnyTLS describes authentication, frames and padding after the TLS handshake; this does not establish that every implementation randomly changes TLS ClientHello.

TUIC is a specification with multiple implementations. One repository's history does not establish the maintenance status of all clients. We checked the primary project's implementation list, not every implementation's security.

Using Chromium reduces stack mismatch but does not provide a mathematical indistinguishability guarantee. The research paper [Fingerprinting Obfuscated Proxy Traffic](https://censorbib.nymity.ch/pdf/Xue2023b.pdf) explains limitations of obfuscation; it is not a measurement of this XIO release or every current NaïveProxy version.

xMUX connection reuse/lifetime, HTTP headers and padding are separate controls. Transport `auto` is not an allowlist detector or an IP discovery mechanism. A CDN needs authorised routing, a suitable service, valid TLS, a reachable ingress and compatible HTTP methods/limits. A TLS terminator can observe its HTTP layer. Inner encryption does not remove sizes, timing and connection metadata.

## Applying the review to RIVET

RIVET/H3 uses outer QUIC/HTTP3 with CONNECT-UDP; S1 uses TLS/WebSocket. The inner channel authenticates independently. An independent TCP path, bounded reassembly and preserving key verification are useful engineering choices.

0.22 does not introduce a new RIVET wire format or relabel Gecko, AnyTLS or NaïveProxy as an XIO invention. It changes automatic candidate policy, checks Xray compatibility and adds managed-server maintenance. Separate upload/download endpoints, browser-stack integration and actual CDN deployments require their own engineering and test work.

| Test | State |
|---|---|
| Several affected Russian operators/regions | No field measurements for this build |
| UDP-unavailable/TCP-available policy | Local logic and integration checks, not a TSPU claim |
| Entire entry IP unreachable | No silent substitution with an unrelated server |
| XHTTP + verified TLS + VLESS Encryption | Four modes × 20 local race-enabled repetitions |
| Broken incoming server executable | Real rollback exercised in an isolated Ubuntu VM |
| DPI/statistical classification and false positives | Not measured; no invented invisibility percentages |

Architecture ideas, local tests and deployed infrastructure remain separately identified.
