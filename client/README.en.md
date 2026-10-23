# XIO Client 0.22.4

A lightweight client for existing servers with yellow-orange branding. Full XIO remains green. [Download prerelease builds](https://github.com/rukazax/xio_vpn/releases/tag/v0.22.4).

Android: 8.0+, ARM32/ARM64/x86-64. Windows and Ubuntu: x64 candidates without new native networking acceptance. iOS: prepared source only, no IPA. The shared profile format is portable, but **full native protocol compatibility is not implemented yet**: 5 engines on Android, 4 on desktop, 2 on iOS.

[Matrix, screenshots, diagram and verification limits](https://github.com/rukazax/xio_vpn/blob/v0.22.4/docs/compatibility/0.22.4.en.md). [Earlier Android features and physical checks](https://github.com/rukazax/xio_vpn/blob/v0.22.4/docs/dualstack/0.22.3.en.md): connection, switching, Android split tunnelling and account-scoped subclients. Server root/admin keys are not transferred to clients. The 0.22.3 network checks are not tests of the new 5013 builds.

## Build / Сборка

Run from the repository root, with Flutter, Python, Go and the native toolchain already installed. Signing credentials are external and never included.

```sh
python3 client/build.py
python3 client/verify.py
python3 client/build_linux.py --go /path/to/go
python3 client/prepare_platform.py windows
python3 client/prepare_platform.py ios
python3 tools/check-protocol-parity.py --require-complete
```

The last command intentionally exits 2 until the missing engines are implemented. Linux packages do not install themselves or enable NAS services. Windows native build: use the prepared `.build-support/client-windows/app` project with `flutter build windows --release --target=lib/client_main.dart --dart-define=XIO_CLIENT_ONLY=true` and bundle the desktop helper/Wintun and dependency licenses. The optional `client/build_windows_on_linux.py --help` documents cross-build inputs; a cross-build is not a Windows network test. iOS requires Mac/Xcode, signing/provisioning and NetworkExtension entitlements; use the prepared client project and the same Dart entry/define. No iOS binary is included.

Exact Android native snapshot: `native-sources/android-runtime-0.22.3`; runtime/AAR is unchanged. Each release includes corresponding source and SHA-256 hashes.
