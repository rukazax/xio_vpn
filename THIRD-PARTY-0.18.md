# XIO0.18.0 distribution terms

Original XIO code, original documentation and UI assets: GPL-3.0-only, Copyright2026 Ерёмин Константин Александрович, er-ka@mail.ru. Upstream files keep their own copyrights and licences; XIO does not claim ownership of them.

The combined Android Go runtime includes GPLv3 Cloak, GPL-3.0-or-later SagerNet sing0.5.1 and sing-shadowsocks0.2.7. Treat the combined client distribution conservatively as GPLv3; JNI or a Flutter platform channel does not by itself provide a proprietary linking exception.

Xray root MPL2.0 does not describe the licences of all linked code. Review MPL secondary-licence compatibility for the actual covered files. OpenVPN3 is used under its expressly available MPL2.0 alternative; MbedTLS under Apache2.0. AmneziaWG Go/tun2socks MIT, bridge Apache2.0, Tailscale/Headscale BSD3, gVisor Apache2.0, Noto OFL1.1. Full module notices remain in app/assets/licenses and vendor files.

The source archive now includes 87 pinned external Go module source ZIPs (including Amnezia Xray, sing and sing-shadowsocks), plus the local Cloak/Tailscale/anet forks and other native/Dart sources. See vendor/go-source-cache/MANIFEST.json and legal/SOURCE-BUILD.ru.md. The inventory is not a warranty of an independent file-by-file licence audit or a fully offline SDK/toolchain bundle.

Keep corresponding sources available alongside each binary release under a suitable GPLv3 distribution method. Send the source archive with private APK deliveries. Publish permanent source directions for Play recipients before releasing publicly. Do not substitute a changing branch for the exact release source.

The APK contains a gzip-compressed server payload with separately executed binaries. Source obligations also apply to those conveyed binaries. APT/DNF-fetched distro services are separate packages; redistributing an image containing them requires reviewing that image's corresponding-source and notice duties.

Licence acknowledgement in the app records reading and disclosure consent; it adds no restrictions to GPL rights and does not waive mandatory consumer rights. Android VPN system permission remains separate.

Legacy HTTPS trust adds four unmodified public root certificate blocks from Mozilla/curl CA data (MPL-2.0). Source URL and verified source digest are in vendor-metadata/probe-trust-roots.json. Only those four roots are included; no trust-all or hostname-verification bypass is used. Native Android and Dart connectivity probes share this subset. This does not update the OS trust store or other applications.
