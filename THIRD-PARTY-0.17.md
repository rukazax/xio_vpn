# XIO 0.17: native components and corresponding source

The Android Go runtime now links Cloak (GPL-3.0). Distribution of this combined
runtime must comply with GPL-3.0, including corresponding source and build scripts.
Do not distribute a binary-only package or remove upstream notices. The source
archive accompanies this private test release; component licenses are also included
in `app/assets/licenses` and accessible through the application's license view.

* Xray: Amnezia Xray fork v1.260728.0, MPL-2.0; exact module graph in
  `protocol/rivet/go.mod` and `go.sum`.
* Cloak: complete fork in `vendor/cloak`; context cancellation and protected-dial
  wrapper are in `xio.go`. No changes to its cryptography.
* Tailscale v1.104.1: `vendor/tailscale`, BSD-3-Clause. Changes add a per-server
  private CA and disable diagnostic log creation/upload when NoLogsNoSupport is set.
* anet v0.0.5: `vendor/anet`; removes unsupported Go-private zone-cache linknames.
* OpenVPN 3: official commit in `vendor/openvpn-deps/SOURCE-PINS.json`, licensed
  under the offered MPL-2.0 alternative. Complete source, including MbedTLS 3.6.7,
  Asio 1.38.2, fmt 12.2.0 and LZ4 1.10.0, is included in `vendor/openvpn-deps`.
* StrongSwan VICI Python: official MIT source in `server/managed/xio_vici`.
* StrongSwan and OpenVPN server executables are installed from distribution
  repositories; they are not bundled into the APK as server binaries.
* Headscale 0.29.5 and Tailscale 1.104.1 server archives are downloaded over TLS
  and checked against `server/managed/mesh-pins.json`.

Build order (Linux x86_64): `tools/build-openvpn.py`,
`tools/build-rivet.py --go .build-support/go/bin/go --gomobile .build-support/go-tools/gomobile`,
`tools/package-server.py`, then `flutter build apk --release --split-per-abi`
in `app`. Use Go 1.27.2, NDK 30.0.16248370, SWIG 4.2, CMake/Ninja and the
Flutter version recorded in the release report. Android signing material is local
and deliberately excluded from the archive. Published binaries must be signed
with the distributor's own key or the existing application's authorized key.
