# Third-party components

This engineering project uses upstream components. The APK includes Flutter-generated license notices, and the font license is retained alongside its asset. Review full transitive notices before public distribution.

| Component | Version/source | License / boundary |
|---|---|---|
| Flutter / Dart | Flutter 3.47.7; `https://github.com/flutter/flutter` | BSD-style Flutter license; SDK and engine have additional notices |
| AmneziaWG Android bridge | commit `ff15093bf3856fea0947923474870b86efb682f0`, upstream versionName 3.1.4 | Apache-2.0; modified sources and provenance in `vendor/amneziawg`; replaces the WireGuard AAR used by 0.1 |
| AmneziaWG Go dataplane / Go runtime | v3.1.20260814 / Go 1.27.2; unified gomobile runtime in0.16 | MIT / BSD; adapted Android handle bridge Apache-2.0. Current transitive notices in `app/assets/licenses/RIVET-native.txt`; historical notices in AmneziaWG-native.txt |
| dartssh2 | 4.1.0, pub.dev; exact dependencies in `pubspec.lock` | MIT as published in package LICENSE |
| cryptography | 2.9.0, pub.dev | Apache-2.0 as published in package LICENSE |
| crypto | 3.0.7, pub.dev | BSD-3-Clause as published in package LICENSE |
| Noto Sans | installed Noto font, bundled offline | SIL Open Font License; see `app/assets/fonts/LICENSE.txt` |
| RIVET transports | coder/websocket 1.8.15, quic-go 0.64.0, masque-go 0.6.0, CBOR 2.9.6; full pins in protocol/rivet/go.mod | MIT / BSD; transitive notices in app/assets/licenses/RIVET-native.txt |
| Tailscale / Headscale | embedded Android Tailscale v1.104.1; pinned server downloads | BSD-3-Clause; patches, notices and source in THIRD-PARTY-0.17.md |
| wireguard-go / gVisor | pinned in `lab/go.mod` and `lab/go.sum` | Included in current Android runtime as well as test fixtures; see upstream MIT / Apache-2.0 licenses |

The research snapshots remain the work of their respective authors and are not part of the xio application binary. This file is an inventory, not a completed legal audit.

Native engine additions and corresponding source: [THIRD-PARTY-0.17.md](THIRD-PARTY-0.17.md).
