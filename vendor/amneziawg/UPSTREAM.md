# AmneziaWG vendored Android bridge

Upstream: https://github.com/amnezia-vpn/amneziawg-android
Pinned commit: ff15093bf3856fea0947923474870b86efb682f0 (versionName 3.1.4).
Go dataplane: github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814;
exact module checksums: go/go.sum. Upstream code retains copyright headers.

Changes in x1o:
- Load `libx1o-awg.so` instead of `libwg-go.so`.
- Minimal Android library Gradle file; Go JNI built by tools/build-amneziawg.py,
  omitting kernel/root command-line tools, UI and upstream app.
- Disable redundant upstream handshake polling thread; x1o has a serialized poller.
- Remove the unused UAPI socket, serialize JNI handle access with a Go mutex,
  and close the device on IpcSet failure without logging rejected config values.
- Disable unsupported always-on metadata in the service manifest.
- Build with private Go 1.27.2 runtime copy, CLOCK_BOOTTIME patch for shipped
  amd64/arm64/arm architectures, NDK 30.0.16248370, min API 26, 16KB ELF alignment.
  Original upstream runtime patch is retained for comparison.

x1o 0.2 uses ONE Go runtime/backend for AWG and standard WireGuard profiles.
The upstream WireGuard Android AAR from x1o 0.1 is no longer a 0.2 dependency.
Loading both runtimes crashed the Android emulator on AWG->WireGuard switching;
the regression test exercises AWG->WireGuard->AWG HTTP traffic in one process.

The three jniLibs binaries are generated, their SHA256 hashes are recorded in
../../vendor-metadata/amneziawg-native.json. Source bundles include these binaries
for immediate buildability; regenerate from pinned source when auditing.

## Android x1o 0.3 integration

- Add an injectable subclass of upstream VpnService; x1o owns the service declaration
  and foreground notification lifecycle. The default class is unchanged for other consumers.
- Stop the created service if JNI activation returns an error.
- Android app supplies X1oVpnService (systemExempted FGS) and VpnTileService.
- Go/JNI binaries are unchanged from 0.2; only the Java service integration changes.

## Android x1o 0.5 routing integration

- Add explicit, DOWN-only `setAllowUnroutedFamilies` for IP split policies. Android
  permits both families outside the narrowed routes even when one remaining route
  is a default route. Default/full-profile behavior keeps the upstream family guard.
- Application-level per-app lists use the existing upstream config and Android API.
- Go/JNI binaries remain unchanged.

## XIO0.16 unified runtime

- The standalone legacy libx1o-awg.so is no longer packaged or loaded by the app.
- org.amnezia.awg.GoBackend retains its Java API but delegates to gomobile's
  app.xio.mobile.Mobile. AWG device/conn/tun v3.1.20260814 is linked into the same
  Go runtime as RIVET, preventing cgo runtime collisions when switching engines.
- The adapted handle/TUN ownership code is protocol/rivet/mobile/awg_unix.go,
  under its original Apache-2.0 attribution. The module retains its MIT notice.
  Local UAPI remains disabled; private configuration strings are not logged.
- The one mobile runtime uses the same private CLOCK_BOOTTIME patch as0.2.
  Crypto/TLS sources are unchanged. Native binary fingerprints now reside in
  vendor-metadata/rivet-build.json. Historical standalone binaries remain
  reference artifacts outside the shipped APK.
