# Build from source

[Русский](../ru/build.md) · [Home](../../README.md)

Download the matching source archive from [Downloads](downloads.md). It includes original code, modified third-party components and pinned dependency sources. SDKs, production signing keys and private profiles are excluded. When building from Git, use the vendor sources matching the release. Do not replace modified forks with arbitrary upstream versions.

Current toolchain: Flutter 3.47.7, Dart 3.13.5, Go 1.27.2 and Python 3.12; Android also needs JDK 17, SDK 36, NDK 30.0.16248370 and CMake/Ninja. Do not automatically upgrade dependencies when reproducing a release.

```sh
cd app
flutter pub get
flutter analyze
flutter test
```

## Android

Restore the Go cache and build native engines using `tools/restore-go-sources.py`, `tools/build-rivet.py`, `tools/build-amneziawg.py` and `tools/build-openvpn.py`. Check each tool's `--help` for arguments. Run `python3 tools/package-server.py` afterwards. [Historical source provenance and offline-build details, Russian](../../legal/SOURCE-BUILD.ru.md).

Configure your own signing key with `tools/create-signing-key.py` or your signing setup. The original publisher's private key is neither needed nor distributed. From `app/`:

```sh
flutter build apk --release --split-per-abi
flutter build appbundle --release
```

Check APKs with `tools/check-android-launcher.py`, `tools/check-native-payload.py`, `apksigner verify` and `zipalign -c -P 16 4`. A different signing key cannot update an installed package signed by another publisher without a separate migration procedure.

## Ubuntu

Install Flutter Linux build dependencies, GTK3 development libraries, CMake/Ninja and Go. Run `tools/build-linux.sh`. Runtime VPN use needs iproute2 and polkit. The UI runs as your user; the network helper requests system authorisation separately.

## Windows

Build on Windows with Flutter, Go and Visual Studio's desktop C++ workload. Run `tools/build-windows.ps1`. Include `data/`, `libexec/xio-tunnel.exe`, the official `wintun.dll` and its licence. Wine verification does not replace testing the driver, UAC, routing and DNS on Windows.

## iOS

Use a Mac with Xcode, the iOS SDK, your Apple Developer team and appropriate NetworkExtension registration. Configure App IDs, app group, keychain group and provisioning. Set `XIO_APPLE_TEAM_ID` and `XIO_IOS_EXPORT_OPTIONS`, then run `tooling/cross-platform/build-ios.sh`. Keep certificates and provisioning secrets out of Git. The iOS source integration currently supports only RIVET/H3 and S1 and needs device testing.

[Licence](../../LICENSE) · [Dependency notices](../../THIRD-PARTY-NOTICES.md) · [Contributing](../../CONTRIBUTING.md)
